//go:build linux && (386 || amd64 || arm64)

package bpffsguard

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Integration test; it loads real eBPF programs and changes mounts, so only
// run it as root inside a disposable mount namespace or VM:
//
//	BPFFSGUARD_INTEGRATION=1 unshare -m --propagation private go test ./pkg/bpffsguard/
func TestMain(m *testing.M) {
	if op := os.Getenv("BPFFSGUARD_HELPER"); op != "" {
		os.Exit(runHelper(op, os.Getenv("BPFFSGUARD_A"), os.Getenv("BPFFSGUARD_B")))
	}
	os.Exit(m.Run())
}

// runHelper performs one mount operation and exits with the resulting errno.
func runHelper(op, a, b string) int {
	var err error
	switch op {
	case "bind":
		err = unix.Mount(a, b, "", unix.MS_BIND, "")
	case "rbind":
		err = unix.Mount(a, b, "", unix.MS_BIND|unix.MS_REC, "")
	case "private":
		err = unix.Mount("", a, "", unix.MS_PRIVATE, "")
	case "rprivate":
		err = unix.Mount("", a, "", unix.MS_PRIVATE|unix.MS_REC, "")
	case "unbindable":
		err = unix.Mount("", a, "", unix.MS_UNBINDABLE, "")
	case "setattr-private":
		err = unix.MountSetattr(unix.AT_FDCWD, a, 0, &unix.MountAttr{Propagation: unix.MS_PRIVATE})
	case "mountbpf":
		err = unix.Mount("bpffs", a, "bpf", 0, "")
	default:
		return 255
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return 0
}

type helperResult struct {
	errno  syscall.Errno
	killed bool
}

func (r helperResult) String() string {
	if r.killed {
		return "SIGKILL"
	}
	if r.errno == 0 {
		return "success"
	}
	return r.errno.Error()
}

func helper(t *testing.T, op, a, b string) helperResult {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "BPFFSGUARD_HELPER="+op, "BPFFSGUARD_A="+a, "BPFFSGUARD_B="+b)
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return helperResult{}
	case errors.As(err, &exitErr):
		ws := exitErr.Sys().(syscall.WaitStatus)
		if ws.Signaled() {
			return helperResult{killed: ws.Signal() == syscall.SIGKILL}
		}
		return helperResult{errno: syscall.Errno(ws.ExitStatus())}
	default:
		t.Fatalf("helper %s: %v", op, err)
		return helperResult{}
	}
}

func expect(t *testing.T, name string, got, want helperResult) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %s, want %s", name, got, want)
	}
}

func isMounted(path string) bool {
	var st, parent unix.Stat_t
	return unix.Stat(path, &st) == nil && unix.Stat(filepath.Dir(path), &parent) == nil && st.Dev != parent.Dev
}

func TestGuardIntegration(t *testing.T) {
	if os.Getenv("BPFFSGUARD_INTEGRATION") != "1" {
		t.Skip("set BPFFSGUARD_INTEGRATION=1 (root, disposable mount namespace)")
	}

	g, err := Start(Options{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Close()
	t.Logf("enforcement mode: %s", g.Mode())

	root := t.TempDir()
	if err := unix.Mount("tmpfs", root, "tmpfs", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(root, unix.MNT_DETACH)
	dir := func(name string) string {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cleanup := func(p string) {
		for isMounted(p) {
			if err := unix.Unmount(p, unix.MNT_DETACH); err != nil {
				t.Fatalf("unmount %s: %v", p, err)
			}
		}
	}
	ok := helperResult{}
	killed := helperResult{killed: true}

	dst := t.TempDir()

	t.Run("protected bpffs cannot be bound", func(t *testing.T) {
		expect(t, "bind", helper(t, "bind", DefaultBPFFSPath, dst), helperResult{errno: unix.EINVAL})
		expect(t, "bind subdir", helper(t, "bind", DefaultBPFFSPath+"/.", dst), helperResult{errno: unix.EINVAL})
		cleanup(dst)
	})

	t.Run("recursive bind skips protected bpffs", func(t *testing.T) {
		expect(t, "rbind /sys", helper(t, "rbind", "/sys", dst), ok)
		var st unix.Statfs_t
		if err := unix.Statfs(filepath.Join(dst, "fs/bpf"), &st); err == nil && uint32(st.Type) == unix.BPF_FS_MAGIC {
			t.Errorf("bpffs was copied by rbind")
		}
		cleanup(dst)
	})

	t.Run("unrelated binds are allowed", func(t *testing.T) {
		expect(t, "bind", helper(t, "bind", dir("plain"), dst), ok)
		cleanup(dst)
	})

	t.Run("bindable bpffs triggers SIGKILL backstop", func(t *testing.T) {
		if !g.KillBackstop {
			t.Skip("backstop not attached")
		}
		fresh := dir("tree/a/bpf")
		expect(t, "mount fresh bpffs", helper(t, "mountbpf", fresh, ""), ok)
		defer cleanup(fresh)
		expect(t, "bind fresh bpffs", helper(t, "bind", fresh, dst), killed)
		cleanup(dst)
		expect(t, "rbind tree mount containing bpffs", helper(t, "rbind", root, dst), killed)
		cleanup(dst)
		expect(t, "rbind sibling subdir", helper(t, "rbind", dir("tree/b"), dst), ok)
		cleanup(dst)
		expect(t, "making it unbindable is allowed", helper(t, "unbindable", fresh, ""), ok)
		expect(t, "bind now-unbindable bpffs", helper(t, "bind", fresh, dst), helperResult{errno: unix.EINVAL})
		cleanup(dst)
	})

	t.Run("propagation changes on protected bpffs", func(t *testing.T) {
		if !g.LSM {
			t.Skip("BPF LSM not active")
		}
		eperm := helperResult{errno: unix.EPERM}
		expect(t, "make-private", helper(t, "private", DefaultBPFFSPath, ""), eperm)
		expect(t, "make-rprivate parent", helper(t, "rprivate", "/sys", ""), eperm)
		expect(t, "mount_setattr private", helper(t, "setattr-private", DefaultBPFFSPath, ""), eperm)
		expect(t, "make-unbindable", helper(t, "unbindable", DefaultBPFFSPath, ""), ok)
		expect(t, "make-rprivate unrelated mount", helper(t, "rprivate", root, ""), ok)
		expect(t, "still unbindable", helper(t, "bind", DefaultBPFFSPath, dst), helperResult{errno: unix.EINVAL})
		cleanup(dst)
	})

	t.Run("exempt process is unrestricted", func(t *testing.T) {
		if err := unix.Mount("", DefaultBPFFSPath, "", unix.MS_PRIVATE, ""); err != nil {
			t.Fatalf("exempt make-private: %v", err)
		}
		if err := unix.Mount(DefaultBPFFSPath, dst, "", unix.MS_BIND, ""); err != nil {
			t.Fatalf("exempt bind: %v", err)
		}
		cleanup(dst)
		if err := markBPFFSUnbindable(); err != nil {
			t.Fatal(err)
		}
	})
}
