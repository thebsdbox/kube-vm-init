//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const maxSocketPath = 4096

type vsockProxy struct {
	fd int
}

func startVSockProxy(portString string) (*vsockProxy, error) {
	port, err := strconv.ParseUint(portString, 10, 32)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid ginit.vsock_port %q", portString)
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("open vsock: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: uint32(port)}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind vsock port %d: %w", port, err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listen on vsock port %d: %w", port, err)
	}
	proxy := &vsockProxy{fd: fd}
	go proxy.serve()
	return proxy, nil
}

func (p *vsockProxy) Close() error { return unix.Close(p.fd) }

func (p *vsockProxy) serve() {
	for {
		fd, _, err := unix.Accept(p.fd)
		if err != nil {
			if !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.EINVAL) {
				log.Errorf("vsock accept: %v", err)
			}
			return
		}
		go func() {
			conn := os.NewFile(uintptr(fd), "vsock")
			defer conn.Close()
			if err := proxyVSockConnection(fd, conn, "/"); err != nil {
				log.Errorf("vsock proxy connection: %v", err)
			}
		}()
	}
}

func guestSocketPath(root, path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) || path == "/" {
		return "", fmt.Errorf("guest Unix socket path must be absolute")
	}
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(path), "/")), nil
}

func proxyVSockConnection(fd int, conn io.ReadWriter, root string) error {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return fmt.Errorf("read socket path length: %w", err)
	}
	n := binary.LittleEndian.Uint16(length[:])
	if n == 0 || n > maxSocketPath {
		return proxyError(conn, fmt.Errorf("invalid socket path length %d", n))
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return fmt.Errorf("read socket path: %w", err)
	}
	target, err := guestSocketPath(root, string(raw))
	if err != nil {
		return proxyError(conn, err)
	}
	unixConn, err := net.Dial("unix", target)
	if err != nil {
		return proxyError(conn, fmt.Errorf("connect %s: %w", raw, err))
	}
	defer unixConn.Close()
	if _, err := conn.Write([]byte{0}); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(unixConn, conn)
		_ = unixConn.(*net.UnixConn).CloseWrite()
		done <- err
	}()
	_, outErr := io.Copy(conn, unixConn)
	if fd >= 0 {
		_ = unix.Shutdown(fd, unix.SHUT_WR)
	}
	inErr := <-done
	if outErr != nil {
		return outErr
	}
	return inErr
}

func proxyError(conn io.Writer, err error) error {
	_, writeErr := fmt.Fprintf(conn, "\x01%s\n", err)
	if writeErr != nil {
		return fmt.Errorf("%w (report error: %v)", err, writeErr)
	}
	return err
}
