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
	swaps, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return proxyError(conn, fmt.Errorf("check guest swap: %w", err))
	}
	if len(strings.Fields(string(swaps))) != 5 {
		return proxyError(conn, fmt.Errorf("disable guest swap before injecting sensitive files"))
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
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		return proxyError(conn, fmt.Errorf("size memfd: %w", err))
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return err
	}
	if err := fillMemoryFile(fd, int(size), conn); err != nil {
		return proxyError(conn, err)
	}
	if err := unix.Fchown(fd, int(owner), int(group)); err != nil {
		return proxyError(conn, fmt.Errorf("set memfd owner: %w", err))
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return proxyError(conn, fmt.Errorf("set memfd mode: %w", err))
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS,
		unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		return proxyError(conn, fmt.Errorf("seal memfd: %w", err))
	}
	memoryMountMu.Lock()
	err = mountMemoryFile(fd, parent, filepath.Base(path))
	memoryMountMu.Unlock()
	if err != nil {
		return proxyError(conn, err)
	}
	_, err = conn.Write([]byte{0})
	return err
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

func mountMemoryFile(memfd, parent int, name string) (result error) {
	// memfd's internal shmem mount is not in this mount namespace, so Linux
	// rejects binding it directly. Project the sealed data through a private
	// tmpfs, then detach the source mount after the file bind pins its pages.
	stage, err := os.MkdirTemp(fmt.Sprintf("/proc/self/fd/%d", parent), ".kube-vm-memory-")
	if err != nil {
		return fmt.Errorf("create memory staging directory: %w", err)
	}
	stagingMounted := false
	defer func() {
		if stagingMounted {
			if err := unix.Unmount(stage, 0); err != nil {
				result = fmt.Errorf("clean up memory staging mount: %v (mount result: %v)", err, result)
				return
			}
		}
		if err := os.Remove(stage); err != nil {
			result = fmt.Errorf("remove empty staging directory: %v (mount result: %v)", err, result)
		}
	}()
	if err := unix.Mount("kube-vm-memory", stage, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0700,size=2m"); err != nil {
		return fmt.Errorf("mount memory staging tmpfs: %w", err)
	}
	stagingMounted = true
	source, err := unix.Open(filepath.Join(stage, "file"), unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0o400)
	if err != nil {
		return fmt.Errorf("create tmpfs projection: %w", err)
	}
	defer unix.Close(source)
	var metadata unix.Stat_t
	if err := unix.Fstat(memfd, &metadata); err != nil {
		return fmt.Errorf("stat sealed memfd: %w", err)
	}
	if metadata.Size != 0 {
		data, err := unix.Mmap(memfd, 0, int(metadata.Size), unix.PROT_READ, unix.MAP_PRIVATE)
		if err != nil {
			return fmt.Errorf("map sealed memfd: %w", err)
		}
		if err := unix.Madvise(data, unix.MADV_DONTDUMP); err != nil {
			unix.Munmap(data)
			return fmt.Errorf("exclude projection from core dumps: %w", err)
		}
		remaining := data
		var writeErr error
		for len(remaining) != 0 {
			n, err := unix.Write(source, remaining)
			if err != nil {
				writeErr = err
				break
			}
			if n == 0 {
				writeErr = io.ErrShortWrite
				break
			}
			remaining = remaining[n:]
		}
		unmapErr := unix.Munmap(data)
		if writeErr != nil {
			return fmt.Errorf("copy sealed memfd into tmpfs: %w", writeErr)
		}
		if unmapErr != nil {
			return fmt.Errorf("unmap sealed memfd: %w", unmapErr)
		}
	}
	if err := unix.Fchown(source, int(metadata.Uid), int(metadata.Gid)); err != nil {
		return fmt.Errorf("set tmpfs owner: %w", err)
	}
	if err := unix.Fchmod(source, metadata.Mode&0o777); err != nil {
		return fmt.Errorf("set tmpfs mode: %w", err)
	}
	target, err := unix.Openat(parent, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	created := err == nil
	if err == unix.EEXIST {
		target, err = unix.Openat(parent, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return fmt.Errorf("open guest mount point: %w", err)
	}
	defer unix.Close(target)
	var stat unix.Stat_t
	if err := unix.Fstat(target, &stat); err != nil {
		return fmt.Errorf("stat guest mount point: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("guest mount point must be a regular file, not a symlink or device")
	}
	destination := fmt.Sprintf("/proc/self/fd/%d", target)
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", source), destination, "", unix.MS_BIND, ""); err != nil {
		if created {
			if cleanupErr := unix.Unlinkat(parent, name, 0); cleanupErr != nil {
				return fmt.Errorf("bind memory file: %w (remove empty mount point: %v)", err, cleanupErr)
			}
		}
		return fmt.Errorf("bind memory file: %w", err)
	}
	// Re-open through the parent: the original descriptor still refers to the
	// covered inode, not the newly mounted tmpfs file.
	mounted, err := unix.Openat(parent, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open mounted memory file: %w", err)
	}
	defer unix.Close(mounted)
	mountPath := fmt.Sprintf("/proc/self/fd/%d", mounted)
	if err := unix.Mount("", mountPath, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		if cleanupErr := unix.Unmount(mountPath, 0); cleanupErr != nil {
			return fmt.Errorf("make memory file read-only: %w (unmount: %v)", err, cleanupErr)
		}
		return fmt.Errorf("make memory file read-only: %w", err)
	}
	return nil
}
