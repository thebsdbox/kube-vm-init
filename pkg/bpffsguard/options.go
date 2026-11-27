// Package bpffsguard loads eBPF programs that stop other processes from bind
// mounting the BPF filesystem (bpffs).
//
// Every bpffs mount is marked MS_UNBINDABLE so the kernel itself rejects bind
// mounts of it. When BPF LSM is active, LSM programs stop non-exempt
// processes from clearing that flag. A fentry program on __do_loopback
// SIGKILLs any non-exempt process that still manages to start a bind of a
// bindable bpffs mount; this is the only enforcement on kernels without BPF
// LSM.
package bpffsguard

// DefaultBPFFSPath is where bpffs is mounted if it isn't already.
const DefaultBPFFSPath = "/sys/fs/bpf"

// Options configures the guard.
type Options struct {
	// BPFFSPath is mounted as bpffs if nothing is mounted there yet.
	// Defaults to DefaultBPFFSPath.
	BPFFSPath string
	// ExemptPIDs are process IDs, as seen from the caller's PID namespace,
	// that are never restricted. The calling process is always exempt.
	ExemptPIDs []uint32
}
