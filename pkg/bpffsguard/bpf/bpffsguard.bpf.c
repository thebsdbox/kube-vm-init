// SPDX-License-Identifier: GPL-2.0
/*
 * bpffsguard: stop processes from bind mounting the BPF filesystem (bpffs).
 *
 * The kernel never hands the *resolved* source of a mount(2) MS_BIND to an
 * LSM hook (security_sb_mount() only sees the raw source string), so the
 * guard relies on the kernel's own MNT_UNBINDABLE enforcement and protects
 * it in layers:
 *
 *  1. Userspace marks every bpffs mount MS_UNBINDABLE. The kernel then
 *     rejects mount --bind / --rbind / open_tree(OPEN_TREE_CLONE) of those
 *     mounts with EINVAL, and recursive binds of a parent skip them.
 *
 *  2. BPF LSM (only when "bpf" is in the active LSM list):
 *     - lsm/sb_mount denies mount(2) propagation changes that would clear
 *       MNT_UNBINDABLE on a bpffs mount (directly or via MS_REC).
 *     - lsm/capable denies CAP_SYS_ADMIN to mount_setattr(2) calls that
 *       change propagation, since that syscall has no mount LSM hook.
 *
 *  3. fentry/__do_loopback (always attached when available): if a bind is
 *     about to clone a bpffs mount that is still bindable, the caller is
 *     sent SIGKILL. This is the fallback when BPF LSM is unavailable.
 *
 * Processes whose TGID, as seen from the loader's PID namespace
 * (pidns_dev/pidns_ino), is in exempt_tgids are never restricted.
 */
#include "kernel.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define BPF_FS_MAGIC 0xcafe4a11UL
#define MNT_UNBINDABLE 0x2000

#define MS_REMOUNT (1UL << 5)
#define MS_BIND (1UL << 12)
#define MS_REC (1UL << 14)
#define MS_SILENT (1UL << 15)
#define MS_UNBINDABLE (1UL << 17)
#define MS_PRIVATE (1UL << 18)
#define MS_SLAVE (1UL << 19)
#define MS_SHARED (1UL << 20)
#define MS_PROPAGATION (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)

#define CAP_SYS_ADMIN 21
#define PF_KTHREAD 0x00200000
#define TS_COMPAT 0x0002
#define SIGKILL 9
#define EPERM 1

#define NR_mount_setattr 442
#define X32_SYSCALL_BIT 0x40000000

/* struct mount_attr (UAPI, stable): propagation is the third __u64. */
#define MOUNT_ATTR_PROPAGATION_OFF 16

#define MAX_WALK_STEPS 8192
#define MAX_DENTRY_DEPTH 64

enum guard_action {
	ACTION_DENY_PROPAGATION = 1,
	ACTION_DENY_MOUNT_SETATTR = 2,
	ACTION_KILL_BIND = 3,
};

struct event {
	u32 tgid;
	u32 pid;
	u32 action;
	u32 pad;
	u64 flags;
	char comm[16];
};

/* Ensure struct event is emitted into BTF so bpf2go generates a Go type. */
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, u8);
} exempt_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

/* Identity of the loader's PID namespace; set before load. */
volatile const u64 pidns_dev;
volatile const u64 pidns_ino;

static __always_inline bool current_is_exempt(void)
{
	struct bpf_pidns_info ns = {};

	/* Fails for tasks outside the loader's PID namespace: not exempt. */
	if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
		return false;
	return bpf_map_lookup_elem(&exempt_tgids, &ns.tgid) != NULL;
}

static __always_inline void emit(u32 action, u64 flags)
{
	struct event *e;
	u64 id;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = (u32)id;
	e->action = action;
	e->pad = 0;
	e->flags = flags;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

static __always_inline struct mount *real_mount(struct vfsmount *vfs)
{
	return (void *)vfs - bpf_core_field_offset(struct mount, mnt);
}

static __always_inline struct mount *mount_from_child(struct list_head *node)
{
	return (void *)node - bpf_core_field_offset(struct mount, mnt_child);
}

static __always_inline bool mount_is_bpffs(struct mount *m)
{
	return BPF_CORE_READ(m, mnt.mnt_sb, s_magic) == BPF_FS_MAGIC;
}

static __always_inline bool mount_is_unbindable(struct mount *m)
{
	return BPF_CORE_READ(m, mnt.mnt_flags) & MNT_UNBINDABLE;
}

/* Bounded equivalent of the kernel's is_subdir(). Errs towards "true". */
static __always_inline bool is_subdir(struct dentry *d, struct dentry *ancestor)
{
	for (int i = 0; i < MAX_DENTRY_DEPTH; i++) {
		struct dentry *parent;

		if (d == ancestor)
			return true;
		parent = BPF_CORE_READ(d, d_parent);
		if (!parent || parent == d)
			return false;
		d = parent;
	}
	return true;
}

enum walk_mode {
	/* Find a bpffs mount that is currently MNT_UNBINDABLE. */
	WALK_PROTECTED_BPFFS,
	/* Mirror copy_tree(): find a bindable bpffs mount that would be cloned. */
	WALK_BINDABLE_BPFFS,
};

struct walk_ctx {
	struct mount *root;
	struct mount *cur;
	/* For WALK_BINDABLE_BPFFS: only children of root mounted below this. */
	struct dentry *root_dentry;
	u32 mode;
	bool descend;
	bool found;
	bool finished;
};

static __always_inline bool walk_matches(struct walk_ctx *w, struct mount *m)
{
	bool bpffs = mount_is_bpffs(m);
	bool unbindable = mount_is_unbindable(m);

	if (w->mode == WALK_PROTECTED_BPFFS)
		return bpffs && unbindable;
	return bpffs && !unbindable;
}

/* Visit a newly reached mount; returns 1 to stop the walk. */
static __always_inline long walk_visit(struct walk_ctx *w, struct mount *m)
{
	w->cur = m;
	w->descend = true;

	if (w->mode == WALK_BINDABLE_BPFFS) {
		if (w->root_dentry && BPF_CORE_READ(m, mnt_parent) == w->root &&
		    !is_subdir(BPF_CORE_READ(m, mnt_mountpoint), w->root_dentry)) {
			w->descend = false;
			return 0;
		}
		/* copy_tree() skips unbindable subtrees entirely. */
		if (mount_is_unbindable(m)) {
			w->descend = false;
			return 0;
		}
	}
	if (walk_matches(w, m)) {
		w->found = true;
		return 1;
	}
	return 0;
}

/* One step of an iterative pre-order walk, equivalent to next_mnt(). */
static long walk_step(u64 index, void *ctx)
{
	struct walk_ctx *w = ctx;
	struct mount *cur = w->cur;

	if (w->descend) {
		struct list_head *head = &cur->mnt_mounts;
		struct list_head *first = BPF_CORE_READ(cur, mnt_mounts.next);

		if (!first || first == head) {
			w->descend = false;
			return 0;
		}
		return walk_visit(w, mount_from_child(first));
	}

	if (cur == w->root) {
		w->finished = true;
		return 1;
	}

	struct mount *parent = BPF_CORE_READ(cur, mnt_parent);
	struct list_head *next = BPF_CORE_READ(cur, mnt_child.next);

	if (!parent || !next) {
		w->finished = true;
		return 1;
	}
	if (next == &parent->mnt_mounts) {
		w->cur = parent;
		return 0;
	}
	return walk_visit(w, mount_from_child(next));
}

/*
 * Returns 1 if a matching mount exists in root's subtree (root excluded),
 * 0 if none, and -1 if the walk could not complete.
 */
static __always_inline int subtree_has(struct mount *root, struct dentry *root_dentry, u32 mode)
{
	struct walk_ctx w = {
		.root = root,
		.cur = root,
		.root_dentry = root_dentry,
		.mode = mode,
		.descend = true,
	};

	bpf_loop(MAX_WALK_STEPS, walk_step, &w, 0);
	if (w.found)
		return 1;
	return w.finished ? 0 : -1;
}

SEC("lsm/sb_mount")
int BPF_PROG(guard_sb_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data, int ret)
{
	struct mount *target;
	int found;

	if (ret)
		return ret;
	/* Only do_change_type() is relevant; path_mount() checks these first. */
	if (flags & (MS_REMOUNT | MS_BIND))
		return 0;
	if (!(flags & MS_PROPAGATION))
		return 0;
	/* Making a mount unbindable never weakens the protection. */
	if ((flags & ~(MS_REC | MS_SILENT)) == MS_UNBINDABLE)
		return 0;
	if (current_is_exempt())
		return 0;

	target = real_mount(BPF_CORE_READ(path, mnt));
	if (mount_is_bpffs(target) && mount_is_unbindable(target))
		goto deny;
	if (flags & MS_REC) {
		found = subtree_has(target, NULL, WALK_PROTECTED_BPFFS);
		/* Fail closed if the mount tree was too large to inspect. */
		if (found != 0)
			goto deny;
	}
	return 0;

deny:
	emit(ACTION_DENY_PROPAGATION, flags);
	return -EPERM;
}

static __always_inline bool task_is_compat(struct task_struct *task)
{
#if defined(__TARGET_ARCH_x86)
	if (bpf_core_field_exists(task->thread_info.status))
		return BPF_CORE_READ(task, thread_info.status) & TS_COMPAT;
#endif
	return false;
}

SEC("lsm/capable")
int BPF_PROG(guard_capable, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts, int ret)
{
	struct task_struct *task;
	struct pt_regs *regs;
	u64 uattr, propagation = 0;
	long nr;

	if (ret || cap != CAP_SYS_ADMIN)
		return ret;

	task = bpf_get_current_task_btf();
	if (BPF_CORE_READ(task, flags) & PF_KTHREAD)
		return 0;

	regs = (struct pt_regs *)bpf_task_pt_regs(task);
#if defined(__TARGET_ARCH_x86)
	nr = BPF_CORE_READ(regs, orig_ax) & ~X32_SYSCALL_BIT;
	uattr = BPF_CORE_READ(regs, r10);
#else
	nr = BPF_CORE_READ(regs, syscallno);
	uattr = BPF_CORE_READ(regs, regs[3]);
#endif
	if (nr != NR_mount_setattr)
		return 0;
	if (current_is_exempt())
		return 0;

	/*
	 * may_mount() runs before the kernel copies struct mount_attr, so the
	 * value is read from userspace here. Fail closed when it can't be read
	 * or the register layout is ambiguous (ia32 compat syscalls).
	 */
	if (task_is_compat(task) ||
	    bpf_probe_read_user(&propagation, sizeof(propagation),
				(void *)(uattr + MOUNT_ATTR_PROPAGATION_OFF)))
		goto deny;
	if (propagation == 0 || propagation == MS_UNBINDABLE)
		return 0;

deny:
	emit(ACTION_DENY_MOUNT_SETATTR, propagation);
	return -EPERM;
}

SEC("fentry/__do_loopback")
int BPF_PROG(backstop_loopback, struct path *old_path, int recurse)
{
	struct task_struct *task;
	struct mount *old;
	struct dentry *dentry;
	u32 tgid = bpf_get_current_pid_tgid() >> 32;

	/* Never signal init or kernel threads. */
	if (tgid <= 1)
		return 0;
	task = bpf_get_current_task_btf();
	if (BPF_CORE_READ(task, flags) & PF_KTHREAD)
		return 0;

	old = real_mount(BPF_CORE_READ(old_path, mnt));
	/* The kernel rejects binds of unbindable mounts on its own. */
	if (mount_is_unbindable(old))
		return 0;
	if (current_is_exempt())
		return 0;

	if (!mount_is_bpffs(old)) {
		if (!recurse)
			return 0;
		dentry = BPF_CORE_READ(old_path, dentry);
		if (dentry == BPF_CORE_READ(old, mnt.mnt_root))
			dentry = NULL;
		if (subtree_has(old, dentry, WALK_BINDABLE_BPFFS) != 1)
			return 0;
	}

	bpf_send_signal(SIGKILL);
	emit(ACTION_KILL_BIND, recurse ? MS_BIND | MS_REC : MS_BIND);
	return 0;
}
