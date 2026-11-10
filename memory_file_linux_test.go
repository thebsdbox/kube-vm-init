//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func memoryFileRequest(path string, data []byte) []byte {
	header := make([]byte, 28)
	copy(header[2:], "KVMFILE1")
	binary.LittleEndian.PutUint16(header[10:], uint16(len(path)))
	binary.LittleEndian.PutUint32(header[12:], uint32(len(data)))
	binary.LittleEndian.PutUint32(header[16:], 0o400)
	return append(append(header, path...), data...)
}

func TestMemoryFileRejectsInvalidRequests(t *testing.T) {
	valid := memoryFileRequest("/token", []byte("secret"))
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"version", append([]byte("\x00\x00BADFILE1"), valid[10:]...)},
		{"relative", memoryFileRequest("relative", nil)},
		{"unclean", memoryFileRequest("/home/../token", nil)},
		{"root", memoryFileRequest("/", nil)},
		{"newline", memoryFileRequest("/token\n", nil)},
		{"missing-header", []byte{0, 0}},
		{"missing-path", valid[:28]},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := &testStream{Reader: bytes.NewReader(test.data)}
			if err := proxyVSockConnection(-1, stream, t.TempDir()); err == nil {
				t.Fatal("accepted invalid request")
			}
			if !bytes.HasPrefix(stream.output.Bytes(), []byte{1}) {
				t.Fatalf("missing failure response: %q", stream.output.Bytes())
			}
		})
	}
	for _, offset := range []int{12, 16, 20, 24} {
		request := bytes.Clone(valid)
		binary.LittleEndian.PutUint32(request[offset:], ^uint32(0))
		stream := &testStream{Reader: bytes.NewReader(request)}
		if err := proxyVSockConnection(-1, stream, t.TempDir()); err == nil {
			t.Fatalf("accepted invalid metadata at %d", offset)
		}
	}
}

func TestMemoryFileRejectsSymlinkParent(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "home")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openMemoryFileParent(root, "/home/token"); err == nil {
		unix.Close(fd)
		t.Fatal("followed symlink directory")
	}
}

func TestFillMemoryFile(t *testing.T) {
	fd, err := unix.MemfdCreate("test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, 6); err != nil {
		t.Fatal(err)
	}
	if err := fillMemoryFile(fd, 6, strings.NewReader("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_WRITE); err != nil {
		t.Fatal("mapping was not released:", err)
	}
	var data [6]byte
	if n, err := unix.Pread(fd, data[:], 0); err != nil || n != 6 || string(data[:]) != "secret" {
		t.Fatalf("read=%q err=%v", data, err)
	}
	if _, err := unix.Pwrite(fd, []byte("X"), 0); err != unix.EPERM {
		t.Fatalf("sealed data remained writable: %v", err)
	}
}

func TestFillMemoryFileRejectsTruncation(t *testing.T) {
	fd, err := unix.MemfdCreate("test", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, 10); err != nil {
		t.Fatal(err)
	}
	if err := fillMemoryFile(fd, 10, strings.NewReader("short")); err == nil {
		t.Fatal("accepted truncated data")
	}
}

func TestMapLockedMemory(t *testing.T) {
	fd, err := unix.MemfdCreate("locked-test", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, int64(os.Getpagesize())); err != nil {
		t.Fatal(err)
	}
	before := vmLockedBytes(t)
	data, err := mapLockedMemory(fd, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseLockedMemory(data)
	if locked := vmLockedBytes(t); locked < before+uint64(os.Getpagesize()) {
		t.Fatalf("locked bytes=%d, want at least %d", locked, before+uint64(os.Getpagesize()))
	}
}

func vmLockedBytes(t *testing.T) uint64 {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "VmLck:") {
			continue
		}
		fields := strings.Fields(line)
		kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return kilobytes * 1024
	}
	t.Fatal("VmLck not found in /proc/self/status")
	return 0
}

func TestMemoryFileMountIntegration(t *testing.T) {
	if os.Getenv("GINIT_MEMORY_MOUNT_TEST") != "1" {
		corePattern, err := os.ReadFile("/proc/sys/kernel/core_pattern")
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(strings.TrimSpace(string(corePattern)), "|") {
			t.Skip("memory-file integration requires piped core dumping disabled")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestMemoryFileMountIntegration$", "-test.v")
		cmd.Env = append(os.Environ(), "GINIT_MEMORY_MOUNT_TEST=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
		output, err := cmd.CombinedOutput()
		if errors.Is(err, syscall.EPERM) {
			t.Skip("mount namespace integration requires CAP_SYS_ADMIN")
		}
		if err != nil {
			t.Fatalf("mount namespace integration: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	home := filepath.Join(root, "home", "ubuntu")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if binary := os.Getenv("GINIT_KUBEVMCTL"); binary != "" {
		testMemoryFileCLI(t, root, binary)
	}
	target := filepath.Join(home, "token.conf")
	for _, data := range [][]byte{[]byte("token\x00contents"), []byte("rotated"), {}, bytes.Repeat([]byte{0xa5}, maxMemoryFile)} {
		request := memoryFileRequest("/home/ubuntu/token.conf", data)
		binary.LittleEndian.PutUint32(request[20:], 1000)
		binary.LittleEndian.PutUint32(request[24:], 1001)
		stream := &testStream{Reader: bytes.NewReader(request)}
		if err := proxyVSockConnection(-1, stream, root); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stream.output.Bytes(), []byte{0, 0}) {
			t.Fatalf("response=%q", stream.output.Bytes())
		}
		got, err := os.ReadFile(target)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("mounted contents=%q err=%v", got, err)
		}
		info, err := os.Stat(target)
		if err != nil || info.Mode().Perm() != 0o400 {
			t.Fatalf("mounted permissions=%v err=%v", info, err)
		}
		owner := info.Sys().(*syscall.Stat_t)
		if owner.Uid != 1000 || owner.Gid != 1001 {
			t.Fatalf("mounted owner=%d:%d", owner.Uid, owner.Gid)
		}
		if err := os.WriteFile(target, []byte("modified"), 0o600); err == nil {
			t.Fatal("mounted memfd was writable")
		}
		var fs unix.Statfs_t
		const requiredFlags = unix.ST_RDONLY | unix.ST_NOEXEC | unix.ST_NOSUID | unix.ST_NODEV
		if err := unix.Statfs(target, &fs); err != nil || fs.Flags&requiredFlags != requiredFlags {
			t.Fatalf("unsafe memory-file mount flags=%x err=%v", fs.Flags, err)
		}
	}
	if locked := vmLockedBytes(t); locked < 1<<20 {
		t.Fatalf("mounted memory files are not retained in locked RAM: %d bytes", locked)
	}
	for range 4 {
		if err := unix.Unmount(target, 0); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(target)
	if err != nil || len(got) != 0 {
		t.Fatalf("underlying disk contains data: %q err=%v", got, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	stream := &testStream{Reader: bytes.NewReader(memoryFileRequest("/home/ubuntu/token.conf", make([]byte, maxMemoryFile+1)))}
	if err := proxyVSockConnection(-1, stream, root); err == nil || !bytes.Equal(stream.output.Bytes()[:1], []byte{1}) {
		t.Fatal("accepted oversized payload or requested its contents")
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("memory staging files remain: %v err=%v", entries, err)
	}
	// No partial upload can create a persistent mount point.
	request := memoryFileRequest("/home/ubuntu/token.conf", []byte("secret"))
	stream = &testStream{Reader: bytes.NewReader(request[:len(request)-1])}
	if err := proxyVSockConnection(-1, stream, root); err == nil {
		t.Fatal("accepted incomplete upload")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("incomplete upload left a mount point: %v", err)
	}
	link := filepath.Join(home, "link")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	stream = &testStream{Reader: bytes.NewReader(memoryFileRequest("/home/ubuntu/link", nil))}
	if err := proxyVSockConnection(-1, stream, root); err == nil {
		t.Fatal("mounted over a symlink")
	}
	// Existing on-disk contents are covered, never truncated.
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	stream = &testStream{Reader: bytes.NewReader(memoryFileRequest("/home/ubuntu/token.conf", []byte("replacement")))}
	if err := proxyVSockConnection(-1, stream, root); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unmount(target, 0); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(target)
	if err != nil || string(got) != "original" {
		t.Fatalf("modified original file: %q err=%v", got, err)
	}
}

func TestProxyErrorIsOneLine(t *testing.T) {
	var out bytes.Buffer
	if err := proxyError(&out, io.ErrUnexpectedEOF); err == nil {
		t.Fatal("error not propagated")
	}
	if bytes.Count(out.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("invalid error framing: %q", out.Bytes())
	}
}
