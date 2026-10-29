//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testStream struct {
	io.Reader
	output bytes.Buffer
}

func (s *testStream) Write(p []byte) (int, error) { return s.output.Write(p) }

func TestGuestSocketPath(t *testing.T) {
	for _, path := range []string{"relative.sock", "/", "/tmp/zero\x00sock"} {
		if _, err := guestSocketPath("/mnt", path); err == nil {
			t.Errorf("accepted invalid path %q", path)
		}
	}
	path, err := guestSocketPath("/mnt", "/run/app.sock")
	if err != nil || path != "/mnt/run/app.sock" {
		t.Fatalf("path = %q, err = %v", path, err)
	}
}

func TestProxyVSockConnection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "run", "echo.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var payload [4]byte
		_, err = io.ReadFull(conn, payload[:])
		if err == nil {
			_, err = conn.Write(bytes.ToUpper(payload[:]))
		}
		done <- err
	}()
	const guestPath = "/run/echo.sock"
	var request bytes.Buffer
	binary.Write(&request, binary.LittleEndian, uint16(len(guestPath)))
	request.WriteString(guestPath)
	request.WriteString("ping")
	stream := &testStream{Reader: bytes.NewReader(request.Bytes())}
	if err := proxyVSockConnection(-1, stream, root); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := stream.output.String(); got != "\x00PING" {
		t.Fatalf("unexpected response %q", got)
	}
}

func TestProxyRejectsInvalidRequest(t *testing.T) {
	var request bytes.Buffer
	binary.Write(&request, binary.LittleEndian, uint16(3))
	request.WriteString("bad")
	stream := &testStream{Reader: bytes.NewReader(request.Bytes())}
	err := proxyVSockConnection(-1, stream, "/mnt")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error = %v", err)
	}

	if !bytes.HasPrefix(stream.output.Bytes(), []byte{1}) {
		t.Fatal("expected failure response")
	}
}

func TestProxyReportsMissingSocket(t *testing.T) {
	const guestPath = "/run/missing.sock"
	var request bytes.Buffer
	binary.Write(&request, binary.LittleEndian, uint16(len(guestPath)))
	request.WriteString(guestPath)
	stream := &testStream{Reader: bytes.NewReader(request.Bytes())}
	if err := proxyVSockConnection(-1, stream, t.TempDir()); err == nil {
		t.Fatal("expected dial failure")
	}
	if !bytes.HasPrefix(stream.output.Bytes(), []byte{1}) || !bytes.HasSuffix(stream.output.Bytes(), []byte{'\n'}) {
		t.Fatalf("missing guest failure response: %q", stream.output.String())
	}
}
