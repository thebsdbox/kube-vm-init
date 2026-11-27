# ginit

I 100% blame Mr Ellis for this..

## What is this?

Good question .. to understand this, we need to understand the boot process!

## The Linux Boot process

`tl;dr` Once a kernel "sorts out" the hardware it does one last thing and that is to start process **1**, which is 🥁 ... the `init` process! 

**Note**: if this `init` process unexpectedly dies (without telling the kernel to reboot or power off), then you'll get a kernel panic! So don't attempt to kill init PEOPLE!

```
[   10.032969] ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000200 ]---
```

The job of `init` is to set up the Linux environment by doing the following:

1. Creating a virtual filesystem
2. Mounting various devices
3. Mounting root filesystems
4. Perhaps do some networking
5. Make a lovely brew
6. Start another process, that may start others (such as systemd)
7. Then wait to be told to power off or reboot etc.. but never die!

## `ginit`

The `ginit` is actually a few things.. but the main part is some go code that will execute as `/init` and set up the environment for you.. in most cases it will then drop to a `busybox` shell. There is where you can modify it to do what ever you like!

### Creating everyting!

The `ginit.sh` script will build the code/busybox and create a initrd container image, it will then extract the initrd.tar.gz to the local filesystem for you. It will also grab you a local copy of the latest Ubuntu Kernel.

### Creating a disk image from a container!

The `image2disk.sh <name:tag>` script will pull a docker image and convert it to a `raw` disk you can then start with `ginit` etc..

### Release builds

Publishing a GitHub release runs [the release workflow](.github/workflows/release.yml)
against the release tag. It builds an x86-64 kernel without modules using
[kernel/build.sh](kernel/build.sh) and the configuration in the kernel folder,
and builds the initramfs using [ginit.sh](ginit.sh). Both builds must succeed
before assets are attached to the release:

- `linux-<kernel-version>-amd64` — bootable kernel image (bzImage).
- `initramfs.cpio.gz` — compressed initramfs.
- `SHA256SUMS` — SHA-256 checksums for both assets.

The kernel configuration ([kernel/.config](kernel/.config)) is a slim,
virtual-machine-only configuration for KVM-based hypervisors such as QEMU,
cloud-hypervisor, and Firecracker. It keeps virtio devices (block, net,
console, vsock, fs, balloon, rng, IOMMU), the emulated devices QEMU uses by
default (AHCI/PIIX disks, e1000/e1000e NICs, the 8250 serial console), TPM,
and the BPF, BTF, and tracing features that Tetragon needs. Nested
virtualization stays enabled (KVM for Intel and AMD, vhost-net, vhost-vsock,
TUN, and bridging). The networking that VM hosts and Kubernetes nodes rely on
is built in: tc qdiscs, classifiers, and actions (including clsact and BPF),
macvlan/macvtap, ipvlan, VLAN, bonding, dummy, ifb, VRF, WireGuard, tunnels
(VXLAN, GENEVE, GRE, IPIP), IPsec, iptables, ipset, IPVS, and socket
diagnostics. Bare-metal hardware support, such as USB, graphics,
sound, wireless, HP iLO, watchdogs, and CPU frequency scaling, is removed.

`kernel/build.sh` builds only `bzImage`. Options that resolve to `=m` are left
out of the kernel rather than built in, and the build fails if Kconfig would
still build any of them in. To include a feature, set it to `=y` in
`kernel/.config`.

The kernel version defaults to **7.3.6**. Set the repository Actions variable
`KERNEL_VERSION` to change the version used for new releases. The workflow also
supports manual runs with an existing `release_tag` and an optional
`kernel_version` override. Reruns replace assets with the same names.
The selected kernel version must be available on kernel.org.

## Starting

```
qemu-system-x86_64 -nographic \
  -kernel ./linux \
  -append "entrypoint=/docker-entrypoint.sh root=/dev/sda console=ttyS0" \
  -initrd ./initramfs.cpio.gz \
  -hda ./disk.img \
  -m 1G
```

Note: the `-append` is where we pass things to be read at runtime.. the k/v entrypoint=.. is where you pass what you want to start from the disk image!

## bpffs bind mount guard

Before starting Tetragon, `ginit` (PID 1) loads the eBPF programs in
`pkg/bpffsguard` to stop any other process from bind mounting the BPF
filesystem (`/sys/fs/bpf`, which holds Tetragon's pinned maps and programs).
Linux never passes the resolved source of a `mount --bind` to an LSM hook, so
the guard works in layers:

1. Every bpffs mount is marked `MS_UNBINDABLE` (`/sys/fs/bpf` is mounted first
   if needed). The kernel then rejects `--bind`, `--rbind` and
   `open_tree(OPEN_TREE_CLONE)` of it with `EINVAL`, and recursive binds of a
   parent skip it.
2. With BPF LSM active (`CONFIG_BPF_LSM=y` and `bpf` in `lsm=`, e.g.
   `lsm=lockdown,capability,landlock,yama,apparmor,bpf`), `lsm/sb_mount` denies
   (`EPERM`) `mount(2)` propagation changes that would clear that flag on a bpffs
   mount, directly or via `MS_REC` on a parent. `lsm/capable` denies
   `mount_setattr(2)` propagation changes (other than to unbindable), because
   that syscall has no mount LSM hook.
3. `fentry/__do_loopback` sends `SIGKILL` to any process that starts a bind of a
   bpffs mount that is still bindable. Without BPF LSM this is the only
   enforcement, and it detects rather than prevents: the bind can still land in
   a mount namespace that other processes share.

Only ginit itself is exempt, so the chroot stage no longer makes its mounts
private itself (PID 1 does it before spawning). Denials and kills are logged.
Known limits: a `mount_setattr` caller racing another thread to rewrite its
`struct mount_attr` can bypass layer 2, though a later bind is still caught by
layer 3. bpffs instances mounted later by other processes stay bindable and are
covered only by layer 3.

The compiled objects are committed. Run `make generate` after changing
`pkg/bpffsguard/bpf/*.c` (needs clang and libbpf headers). To run the
integration test (root, disposable environment):

```
BPFFSGUARD_INTEGRATION=1 unshare -m --propagation private go test ./pkg/bpffsguard/
```

## Troubleshooting..

Just cross your fingers it works first time?
# Unix socket forwarding over virtio-vsock

When the VM is launched with a virtio-vsock device, append
`ginit.vsock_port=1024` to its kernel command line (use the same port selected
by the VM's `--vsock` flag). The init listens on that port after mounting the
root filesystem. Each connection specifies an absolute path in the guest root
as a two-byte little-endian length followed by the path; the init connects to
that Unix socket and replies with `0` on success, or `1` and a newline-terminated
error on failure. It then forwards bytes in both directions. The proxy is
disabled when the command-line option is absent.

On the host, `kube-vmctl vsock --uid VM --listen /tmp/app.sock /run/app.sock`
provides a local Unix socket connected to `/run/app.sock` in the guest. Restrict
access to the host socket: callers can select any guest Unix socket path.

The service runs as a separate process inside the OS entrypoint's chroot and
mount namespace. It survives the entrypoint exec so files mounted after boot
are visible in the running OS, including when its mounts are private. Only the
host vsock CID is accepted. Startup errors are reported before the entrypoint
is executed.

## Memory-only file injection

An updated `kubevmctl` can send live data over the same vsock port:

```sh
kubevmctl inject-file --uid VM --source - \
  --guest-uid 1000 --guest-gid 1000 /home/ubuntu/token.conf < /secure/token
```

Pipe a token provider to stdin instead if the source must not exist on host
storage. The maximum size is 1 MiB; empty and binary files are supported.
The guest parent directory must already exist and have its final OS mount in
place. Paths must be clean and absolute, with no symlink components; the target
must be absent or a regular file. Ownership defaults to root; `--mode` defaults
to `0400` and only read-only modes such as `0440` are accepted.

Data is received into a memory-locked memfd, which is sealed after transfer.
Linux rejects binding a memfd directly because its internal shmem mount is
outside the mount namespace.
The service therefore locks a private tmpfs file's mapping before copying the
contents into it, binds that file read-only with `nosuid,nodev,noexec`, and removes
the temporary source mount. The service retains the locked mapping until VM
shutdown, keeping its pages in RAM even when guest swap is enabled.
The vsock service must remain alive while injected mounts are in use; terminating
it releases the locks even though the bind mounts may remain.
Neither the base image nor its CoW overlay receives any payload. A new on-disk
mount point is empty; an existing file is covered without changing its original
contents. Re-injection stacks a replacement mount, so covered versions and
already-open descriptors may retain previous values until shutdown.

The incoming memfd is locked before the host is asked to send payload bytes.
Injected data, including replaced versions, consumes locked RAM until the VM
shuts down; the service fails closed if the OS cannot lock the required pages.
`memfd_secret` cannot directly back the guest's normal file path, and copying its
contents into tmpfs would require locking that separate projection too. `mlock`
prevents swapping but does not exclude pages from hibernation, so keep hibernation
disabled as well as piped guest core-dump handlers (which can ignore a zero
core-size limit). The paired host
CLI must first obtain the daemon's `protect-memory` acknowledgment, which
rejects host swap and permanently disables both disk-backed pause (including
automatic idle RAM spill) and snapshots for that VM. This handshake is a
trusted-host responsibility, not guest authentication of the host daemon.
In-memory pause/resume remains supported. Service core dumps are disabled;
the entrypoint inherits a zero core-size limit when vsock is enabled.

Keep hibernation, kernel crash dumps and piped guest core-dump handlers disabled
throughout the VM's lifetime. Guest swap may remain enabled for paging the rest
of the system; injected files remain locked in RAM. This is not protection against
privileged host/guest administrators, memory forensics, or guest applications
writing the tokens to persistent files or logs. Restrict access to the host
bridge socket; its callers can inject files as guest root.

### Wire protocol

Legacy Unix-socket requests are unchanged. A zero two-byte path length selects
memory-file injection, followed by the following fields in order:

| Field | Encoding |
| --- | --- |
| Magic/version | 8 bytes: `KVMFILE1` |
| Path length | little-endian uint16, 1-4096 |
| Payload length | little-endian uint32, 0-1048576 |
| Mode | little-endian uint32, nonzero subset of `0444` |
| Owner UID | little-endian uint32, excluding 4294967295 |
| Owner GID | little-endian uint32, excluding 4294967295 |
| Destination | exactly path-length bytes, no terminator |

The guest validates metadata, checks swap, opens the destination parent without
following symlinks, and allocates the memfd before replying with byte `0`.
Only then does the host send exactly payload-length bytes. After mounting, the
guest replies with byte `0` again. At either stage a failure is byte `1` followed
by a bounded, newline-terminated error. A legacy init rejects the zero-length
request, so a new host does not send its sensitive payload to an old init.
Injection socket reads/writes have a 30-second timeout; the host uses a
30-second overall deadline. An interrupted or truncated transfer is never
mounted. A lost final acknowledgment is ambiguous: the mount may have succeeded.

### Validation

`go test . -run 'Test(MemoryFile|FillMemoryFile|MapLockedMemory|Proxy|GuestSocket)'`
covers framing, errors, bounds, locked-memory accounting, memfd seals, and actual
Linux mount behavior. The mount integration test creates a private mount namespace
and needs `CAP_SYS_ADMIN`; restricted environments skip that test. It verifies
read-only mounts, binary and empty uploads, replacement, symlink rejection,
truncation, and unchanged on-disk contents after unmounting.

Set `GINIT_KUBEVMCTL` to the absolute path of a built companion `kubevmctl`
binary to additionally exercise the real CLI against the guest handler through
a Unix transport bridge, with a stub control daemon. This checks cross-project
wire compatibility and mount visibility across exec; it does not boot a VM or
exercise virtio-vsock hardware.
