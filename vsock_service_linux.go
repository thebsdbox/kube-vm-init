//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// A separate process survives the entrypoint exec while retaining its private
// mount namespace and chroot. Mounts made by an initramfs-side proxy are hidden
// from an OS whose mounts have already been marked private.
func launchVSockService(port string) error {
	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create vsock readiness pipe: %w", err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "GINIT_VSOCK_SERVICE="+port)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{writer}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start vsock service: %w", err)
	}
	writer.Close()
	if err := reader.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("set vsock readiness deadline: %w", err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(reader, ready[:]); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("wait for vsock service: %w", err)
	}
	return nil
}
