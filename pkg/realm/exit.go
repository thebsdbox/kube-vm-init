//go:build linux
// +build linux

package realm

import (
	"os"
	"syscall"

	"fmt"
	"log/slog"
)

// This contains all methods for managing the final steps with a host

// Reboot a host
func Reboot() {
	err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
	if err != nil {
		slog.Error(fmt.Sprintf("reboot off failed: %v", err))
		Shell()
	}
	// Should cause a panic
	os.Exit(1)
}

// PowerOff will result in the host using an ACPI power off
func PowerOff() {
	err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	if err != nil {
		slog.Error(fmt.Sprintf("power off failed: %v", err))
		Shell()
	}
	// Should cause a panic
	os.Exit(1)
}

// Halt will instruct the CPU to enter a halt state (no-power off (usually))
func Halt() {
	err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_HALT)
	if err != nil {
		slog.Error(fmt.Sprintf("halt failed: %v", err))
		Shell()
	}
	// Should cause a panic
	os.Exit(1)
}

// Suspend will instruct the CPU to enter a suspended state (no-power off (usually))
func Suspend() {
	err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_SW_SUSPEND)
	if err != nil {
		slog.Error(fmt.Sprintf("suspend failed: %v", err))
		Shell()
		slog.Warn("Attempting a reboot")
		Reboot()
	}
}
