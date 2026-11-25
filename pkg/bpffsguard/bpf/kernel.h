/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * Minimal kernel type definitions for bpffsguard.
 *
 * Only the fields that are actually accessed are declared. Every struct is
 * marked preserve_access_index so field offsets are relocated against the
 * running kernel's BTF (CO-RE), which keeps a single object file portable
 * across kernel versions without shipping a full vmlinux.h.
 */
#ifndef __BPFFSGUARD_KERNEL_H
#define __BPFFSGUARD_KERNEL_H

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef __u8 u8;
typedef __u32 u32;
typedef __s32 s32;
typedef __u64 u64;
typedef _Bool bool;
#define true 1
#define false 0
#define NULL ((void *)0)

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct super_block {
	unsigned long s_magic;
};

struct dentry {
	struct dentry *d_parent;
	struct super_block *d_sb;
};

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
};

/* fs/mount.h (private to the VFS, but present in BTF). */
struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	struct list_head mnt_mounts;
	struct list_head mnt_child;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct thread_info {
	__u32 status;
};

struct task_struct {
	struct thread_info thread_info;
	unsigned int flags;
};

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r10;
	unsigned long r8;
	unsigned long orig_ax;
};
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
	__u64 regs[31];
	__s32 syscallno;
};
#else
#error "bpffsguard: unsupported target architecture"
#endif

#pragma clang attribute pop

/* UAPI */
struct bpf_pidns_info {
	__u32 pid;
	__u32 tgid;
};

struct cred;
struct user_namespace;

#endif /* __BPFFSGUARD_KERNEL_H */
