package realm

import (
	"os"
	"os/exec"

	"fmt"
	"log/slog"
)

// Shell will Start a userland shell
func Shell() {
	// Shell stuff
	slog.Info("Starting Shell 🐚")

	// TTY hack to support ctrl+c
	cmd := exec.Command("/usr/bin/setsid", "cttyhack", "/bin/sh")
	//cmd := exec.Command("/bin/sh")

	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	err := cmd.Start()
	if err != nil {
		slog.Error(fmt.Sprintf("Shell error [%v]", err))
	}
	err = cmd.Wait()
	if err != nil {
		slog.Error(fmt.Sprintf("Shell error [%v]", err))
	}
}
