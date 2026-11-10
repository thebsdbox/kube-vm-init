//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const maxMemoryFile = 1 << 20

var memoryMountMu sync.Mutex
var memoryLockedFiles [][]byte

func receiveMemoryFile(conn io.ReadWriter, root string) error {
	var header [26]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return proxyError(conn, fmt.Errorf("read memory-file header: %w", err))
	}
	if string(header[:8]) != "KVMFILE1" {
		return proxyError(conn, fmt.Errorf("unsupported memory-file protocol"))
	}
	pathLen := binary.LittleEndian.Uint16(header[8:])
	size := binary.LittleEndian.Uint32(header[10:])
	mode := binary.LittleEndian.Uint32(header[14:])
	owner := binary.LittleEndian.Uint32(header[18:])
	group := binary.LittleEndian.Uint32(header[22:])
	if pathLen == 0 || pathLen > maxSocketPath || size > maxMemoryFile ||
		mode == 0 || mode&^0o444 != 0 || owner == ^uint32(0) || group == ^uint32(0) {
		return proxyError(conn, fmt.Errorf("invalid memory-file metadata"))
	}
	raw := make([]byte, pathLen)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return proxyError(conn, fmt.Errorf("read memory-file path: %w", err))
	}
	path := string(raw)
	if !filepath.IsAbs(path) || path == "/" || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\n\r") {
		return proxyError(conn, fmt.Errorf("memory-file path must be a clean absolute file path"))
	}
	corePattern, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		return proxyError(conn, fmt.Errorf("check guest core-dump handler: %w", err))
	}
	if strings.HasPrefix(strings.TrimSpace(string(corePattern)), "|") {
		return proxyError(conn, fmt.Errorf("disable the piped guest core-dump handler before injecting sensitive files"))
	}
	parent, err := openMemoryFileParent(root, path)
	if err != nil {
		return proxyError(conn, err)
	}
	defer unix.Close(parent)
	fd, err := unix.MemfdCreate("kube-vm-secret", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return proxyError(conn, fmt.Errorf("create memfd: %w", err))
	}
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		return proxyError(conn, fmt.Errorf("size memfd: %w", err))
	}
	payload, err := mapLockedMemory(fd, int(size), unix.PROT_READ|unix.PROT_WRITE)
	if err != nil {
		return proxyError(conn, fmt.Errorf("lock incoming memory file: %w", err))
	}
	fdOpen := true
	defer func() {
		if len(payload) != 0 {
			clear(payload)
		}
		if fdOpen {
			_ = unix.Close(fd)
		}
		releaseLockedMemory(payload)
	}()
	if _, err := conn.Write([]byte{0}); err != nil {
		return err
	}
	if len(payload) != 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return proxyError(conn, fmt.Errorf("read memory-file contents: %w", err))
		}
	}
	if err := unix.Fchown(fd, int(owner), int(group)); err != nil {
		return proxyError(conn, fmt.Errorf("set memfd owner: %w", err))
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return proxyError(conn, fmt.Errorf("set memfd mode: %w", err))
	}
	memoryMountMu.Lock()
	var projection []byte
	projection, err = mountMemoryFile(fd, payload, parent, filepath.Base(path))
	if len(projection) != 0 {
		memoryLockedFiles = append(memoryLockedFiles, projection)
	}
	memoryMountMu.Unlock()
	if len(payload) != 0 {
		clear(payload)
		releaseLockedMemory(payload)
		payload = nil
	}
	if _, sealErr := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS,
		unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); sealErr != nil {
		if err == nil {
			err = fmt.Errorf("seal memfd: %w", sealErr)
		}
	}
	if err != nil {
		return proxyError(conn, err)
	}
	if err := unix.Close(fd); err != nil {
		fdOpen = false
		return proxyError(conn, fmt.Errorf("close sealed memfd: %w", err))
	}
	fdOpen = false
	_, err = conn.Write([]byte{0})
	return err
}

func mapLockedMemory(fd, size, protection int) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	data, err := unix.Mmap(fd, 0, size, protection, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	if err := unix.Madvise(data, unix.MADV_DONTDUMP); err != nil {
		unix.Munmap(data)
		return nil, err
	}
	if err := unix.Mlock(data); err != nil {
		unix.Munmap(data)
		return nil, err
	}
	return data, nil
}

func releaseLockedMemory(data []byte) {
	if len(data) == 0 {
		return
	}
	_ = unix.Munlock(data)
	_ = unix.Munmap(data)
}

func fillMemoryFile(fd, size int, input io.Reader) error {
	if size == 0 {
		return nil
	}
	data, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("map memfd: %w", err)
	}
	if err := unix.Madvise(data, unix.MADV_DONTDUMP); err != nil {
		unix.Munmap(data)
		return fmt.Errorf("exclude memfd from core dumps: %w", err)
	}
	_, readErr := io.ReadFull(input, data)
	unmapErr := unix.Munmap(data)
	if readErr != nil {
		return fmt.Errorf("read memory-file contents: %w", readErr)
	}
	if unmapErr != nil {
		return fmt.Errorf("unmap memfd: %w", unmapErr)
	}
	return nil
}

// Walk directory descriptors without following symlinks, including absolute
// guest symlinks that would otherwise escape a test/chroot root.
func openMemoryFileParent(root, path string) (int, error) {
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open guest root: %w", err)
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open guest destination directory: %w", err)
		}
		fd = next
	}
	return fd, nil
}

func mountMemoryFile(memfd int, payload []byte, parent int, name string) (projection []byte, result error) {
	// memfd's internal shmem mount is not in this mount namespace, so Linux
	// rejects binding it directly. Project the locked data through a private
	// tmpfs, then detach the source mount after the file bind pins its pages.
	stage, err := os.MkdirTemp(fmt.Sprintf("/proc/self/fd/%d", parent), ".kube-vm-memory-")
	if err != nil {
		return nil, fmt.Errorf("create memory staging directory: %w", err)
	}
	stagingMounted := false
	projectionLocked := false
	keepProjection := false
	defer func() {
		if projectionLocked && !keepProjection {
			releaseLockedMemory(projection)
		}
		if stagingMounted {
			// The destination bind mount still references a file on this
			// tmpfs, so detach the staging mount rather than requiring it to
			// be immediately unmountable.
			if err := unix.Unmount(stage, unix.MNT_DETACH); err != nil {
				result = fmt.Errorf("clean up memory staging mount: %v (mount result: %v)", err, result)
				return
			}
		}
		if err := os.Remove(stage); err != nil {
			result = fmt.Errorf("remove empty staging directory: %v (mount result: %v)", err, result)
		}
	}()
	if err := unix.Mount("kube-vm-memory", stage, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0700,size=2m"); err != nil {
		return nil, fmt.Errorf("mount memory staging tmpfs: %w", err)
	}
	stagingMounted = true
	source, err := unix.Open(filepath.Join(stage, "file"), unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0o400)
	if err != nil {
		return nil, fmt.Errorf("create tmpfs projection: %w", err)
	}
	defer unix.Close(source)
	if err := unix.Ftruncate(source, int64(len(payload))); err != nil {
		return nil, fmt.Errorf("size tmpfs projection: %w", err)
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(memfd, &metadata); err != nil {
		return nil, fmt.Errorf("stat sealed memfd: %w", err)
	}
	if len(payload) != 0 {
		projection, err = mapLockedMemory(source, len(payload), unix.PROT_READ|unix.PROT_WRITE)
		if err != nil {
			return nil, fmt.Errorf("lock tmpfs projection: %w", err)
		}
		projectionLocked = true
		copy(projection, payload)
		if err := unix.Mprotect(projection, unix.PROT_READ); err != nil {
			return nil, fmt.Errorf("protect tmpfs projection: %w", err)
		}
	}
	if err := unix.Fchown(source, int(metadata.Uid), int(metadata.Gid)); err != nil {
		return nil, fmt.Errorf("set tmpfs owner: %w", err)
	}
	if err := unix.Fchmod(source, metadata.Mode&0o777); err != nil {
		return nil, fmt.Errorf("set tmpfs mode: %w", err)
	}
	target, err := unix.Openat(parent, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	created := err == nil
	if err == unix.EEXIST {
		target, err = unix.Openat(parent, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open guest mount point: %w", err)
	}
	defer unix.Close(target)
	var stat unix.Stat_t
	if err := unix.Fstat(target, &stat); err != nil {
		return nil, fmt.Errorf("stat guest mount point: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("guest mount point must be a regular file, not a symlink or device")
	}
	destination := fmt.Sprintf("/proc/self/fd/%d", target)
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", source), destination, "", unix.MS_BIND, ""); err != nil {
		if created {
			if cleanupErr := unix.Unlinkat(parent, name, 0); cleanupErr != nil {
				return nil, fmt.Errorf("bind memory file: %w (remove empty mount point: %v)", err, cleanupErr)
			}
		}
		return nil, fmt.Errorf("bind memory file: %w", err)
	}
	keepProjection = true
	// Re-open through the parent: the original descriptor still refers to the
	// covered inode, not the newly mounted tmpfs file.
	mounted, err := unix.Openat(parent, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return projection, fmt.Errorf("open mounted memory file: %w", err)
	}
	defer unix.Close(mounted)
	mountPath := fmt.Sprintf("/proc/self/fd/%d", mounted)
	if err := unix.Mount("", mountPath, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		if cleanupErr := unix.Unmount(mountPath, 0); cleanupErr != nil {
			return projection, fmt.Errorf("make memory file read-only: %w (unmount: %v)", err, cleanupErr)
		}
		keepProjection = false
		return nil, fmt.Errorf("make memory file read-only: %w", err)
	}
	return projection, nil
}
