//go:build linux && (386 || amd64 || arm64)

package bpffsguard

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	securityFSPath = "/sys/kernel/security"
	mountInfoPath  = "/proc/self/mountinfo"
)

// Guard holds the loaded eBPF objects. They stay attached until Close.
type Guard struct {
	maps   bpfMaps
	progs  []*ebpf.Program
	links  []link.Link
	reader *ringbuf.Reader

	// LSM reports whether the BPF LSM programs are enforcing.
	LSM bool
	// KillBackstop reports whether the __do_loopback SIGKILL backstop is attached.
	KillBackstop bool
}

// Start prepares bpffs, loads and attaches the guard programs.
func Start(opts Options) (*Guard, error) {
	if opts.BPFFSPath == "" {
		opts.BPFFSPath = DefaultBPFFSPath
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	if err := ensureBPFFS(opts.BPFFSPath); err != nil {
		return nil, err
	}
	if err := markBPFFSUnbindable(); err != nil {
		return nil, err
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load bpffsguard spec: %w", err)
	}

	var pidns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &pidns); err != nil {
		return nil, fmt.Errorf("stat pid namespace: %w", err)
	}
	if err := spec.Variables["pidns_dev"].Set(uint64(pidns.Dev)); err != nil {
		return nil, err
	}
	if err := spec.Variables["pidns_ino"].Set(pidns.Ino); err != nil {
		return nil, err
	}

	g := &Guard{}
	if err := spec.LoadAndAssign(&g.maps, nil); err != nil {
		return nil, fmt.Errorf("load bpffsguard maps: %w", err)
	}
	exempt := append([]uint32{uint32(os.Getpid())}, opts.ExemptPIDs...)
	for _, pid := range exempt {
		if err := g.maps.ExemptTgids.Put(pid, uint8(1)); err != nil {
			g.Close()
			return nil, fmt.Errorf("exempt pid %d: %w", pid, err)
		}
	}

	lsmActive, err := bpfLSMActive()
	if err != nil {
		log.Warnf("bpffsguard: unable to determine active LSMs: %v", err)
	}
	if lsmActive {
		err = g.attach(spec, "guard_sb_mount", attachLSM)
		if err == nil {
			err = g.attach(spec, "guard_capable", attachLSM)
		}
		if err != nil {
			g.Close()
			return nil, fmt.Errorf("attach BPF LSM programs: %w", err)
		}
		g.LSM = true
	}

	if err := g.attach(spec, "backstop_loopback", attachTracing); err != nil {
		if !g.LSM {
			g.Close()
			return nil, fmt.Errorf("BPF LSM is not active and the SIGKILL backstop failed: %w", err)
		}
		log.Warnf("bpffsguard: SIGKILL backstop unavailable: %v", err)
	} else {
		g.KillBackstop = true
	}

	g.reader, err = ringbuf.NewReader(g.maps.Events)
	if err != nil {
		g.Close()
		return nil, fmt.Errorf("open event ring buffer: %w", err)
	}
	go g.logEvents()

	return g, nil
}

// Mode describes the active enforcement.
func (g *Guard) Mode() string {
	switch {
	case g.LSM && g.KillBackstop:
		return "lsm+sigkill"
	case g.LSM:
		return "lsm"
	default:
		return "sigkill"
	}
}

// Close detaches and unloads everything.
func (g *Guard) Close() error {
	var errs []error
	if g.reader != nil {
		errs = append(errs, g.reader.Close())
	}
	for _, l := range g.links {
		errs = append(errs, l.Close())
	}
	for _, p := range g.progs {
		errs = append(errs, p.Close())
	}
	errs = append(errs, g.maps.Close())
	return errors.Join(errs...)
}

func attachTracing(p *ebpf.Program) (link.Link, error) {
	return link.AttachTracing(link.TracingOptions{Program: p})
}

func attachLSM(p *ebpf.Program) (link.Link, error) {
	return link.AttachLSM(link.LSMOptions{Program: p})
}

// attach loads a single program from spec (so an unsupported attach target
// doesn't prevent the others from loading) and attaches it.
func (g *Guard) attach(spec *ebpf.CollectionSpec, name string, attachFn func(*ebpf.Program) (link.Link, error)) error {
	var objs struct {
		Prog *ebpf.Program `ebpf:"prog"`
	}
	ps, ok := spec.Programs[name]
	if !ok {
		return fmt.Errorf("program %s not found", name)
	}
	single := &ebpf.CollectionSpec{
		Maps:      spec.Maps,
		Programs:  map[string]*ebpf.ProgramSpec{"prog": ps},
		Variables: spec.Variables,
		Types:     spec.Types,
		ByteOrder: spec.ByteOrder,
	}
	err := single.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"events":       g.maps.Events,
			"exempt_tgids": g.maps.ExemptTgids,
		},
	})
	if err != nil {
		return fmt.Errorf("load %s: %w", name, err)
	}

	l, err := attachFn(objs.Prog)
	if err != nil {
		objs.Prog.Close()
		return fmt.Errorf("attach %s: %w", name, err)
	}
	g.progs = append(g.progs, objs.Prog)
	g.links = append(g.links, l)
	return nil
}

func (g *Guard) logEvents() {
	for {
		rec, err := g.reader.Read()
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				log.Errorf("bpffsguard: reading events: %v", err)
			}
			return
		}
		if len(rec.RawSample) < int(unsafe.Sizeof(bpfEvent{})) {
			continue
		}
		e := (*bpfEvent)(unsafe.Pointer(&rec.RawSample[0]))
		log.Warnf("bpffsguard: %s (pid=%d tgid=%d comm=%q flags=%#x)",
			actionString(e.Action), e.Pid, e.Tgid, commString(e.Comm), e.Flags)
	}
}

func actionString(a uint32) string {
	switch a {
	case 1:
		return "denied mount propagation change on protected bpffs"
	case 2:
		return "denied mount_setattr propagation change"
	case 3:
		return "killed process binding bpffs"
	default:
		return fmt.Sprintf("unknown action %d", a)
	}
}

func commString(c [16]int8) string {
	b := make([]byte, 0, len(c))
	for _, v := range c {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func ensureBPFFS(path string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err == nil && uint32(st.Type) == unix.BPF_FS_MAGIC {
		return nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := unix.Mount("bpffs", path, "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs at %s: %w", path, err)
	}
	return nil
}

func markBPFFSUnbindable() error {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return err
	}
	defer f.Close()
	points, err := bpffsMountPoints(f)
	if err != nil {
		return fmt.Errorf("parse %s: %w", mountInfoPath, err)
	}
	for _, p := range points {
		// Overmounted or unreachable paths can't be marked; the SIGKILL
		// backstop still covers binds of any bpffs left bindable.
		if err := unix.Mount("", p, "", unix.MS_UNBINDABLE, ""); err != nil {
			log.Warnf("bpffsguard: unable to mark %s unbindable: %v", p, err)
		}
	}
	return nil
}

// bpfLSMActive reports whether "bpf" is in the kernel's active LSM list,
// mounting securityfs first if needed. BPF LSM programs load and attach even
// when the LSM is compiled in but not enabled; they just never run.
func bpfLSMActive() (bool, error) {
	lsmFile := securityFSPath + "/lsm"
	if _, err := os.Stat(lsmFile); errors.Is(err, os.ErrNotExist) {
		if err := unix.Mount("securityfs", securityFSPath, "securityfs", 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return false, fmt.Errorf("mount securityfs: %w", err)
		}
	}
	b, err := os.ReadFile(lsmFile)
	if errors.Is(err, os.ErrNotExist) {
		// Kernel built without CONFIG_SECURITY.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if l == "bpf" {
			return true, nil
		}
	}
	return false, nil
}
