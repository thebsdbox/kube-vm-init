//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testMemoryFileCLI(t *testing.T, root, binary string) {
	t.Helper()
	controlPath := filepath.Join(t.TempDir(), "c.sock")
	control, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlPath})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	sum := sha256.Sum256([]byte("vm"))
	bridge, err := net.ListenUnix("unix", &net.UnixAddr{Name: fmt.Sprintf("%s.vsock-%x", controlPath, sum[:8])})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	_ = bridge.SetDeadline(time.Now().Add(10 * time.Second))
	controlDone, guestDone := make(chan error, 1), make(chan error, 1)
	go func() {
		for _, action := range []string{"list", "protect-memory"} {
			conn, err := control.Accept()
			if err != nil {
				controlDone <- err
				return
			}
			var request struct {
				Action  string            `json:"action"`
				Payload map[string]string `json:"payload"`
			}
			err = json.NewDecoder(conn).Decode(&request)
			if err == nil && (request.Action != action || action == "protect-memory" && request.Payload["uid"] != "vm") {
				err = fmt.Errorf("unexpected control request: %+v", request)
			}
			if err == nil {
				response := map[string]any{"ok": true, "vms": []map[string]string{{"uid": "vm"}}}
				err = json.NewEncoder(conn).Encode(response)
			}
			conn.Close()
			if err != nil {
				controlDone <- err
				return
			}
		}
		controlDone <- nil
	}()
	go func() {
		conn, err := bridge.Accept()
		if err != nil {
			guestDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		guestDone <- proxyVSockConnection(-1, conn, root)
	}()
	data := []byte("live-token\x00binary")
	cmd := exec.Command(binary, "--socket", controlPath, "--uid", "vm", "inject-file",
		"--source", "-", "--guest-uid", "1000", "/home/ubuntu/from-cli")
	cmd.Stdin = bytes.NewReader(data)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real kubevmctl injection: %v\n%s", err, output)
	}
	if err := <-controlDone; err != nil {
		t.Fatal(err)
	}
	if err := <-guestDone; err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "home/ubuntu/from-cli")
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("real CLI mounted data=%q err=%v", got, err)
	}
	// A second process sees the mount after exec, as the OS entrypoint does.
	output, err = exec.Command("cat", target).Output()
	if err != nil || !bytes.Equal(output, data) {
		t.Fatalf("mounted data is not visible across exec: %v", err)
	}
	if err := unix.Unmount(target, 0); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(target)
	if err != nil || len(got) != 0 {
		t.Fatalf("CLI wrote payload to underlying storage: %q err=%v", got, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
}
