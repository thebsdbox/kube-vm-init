//go:build !linux || !(386 || amd64 || arm64)

package bpffsguard

import "errors"

// Guard is unavailable on this platform.
type Guard struct {
	LSM          bool
	KillBackstop bool
}

// Start always fails on platforms without a compiled eBPF object.
func Start(Options) (*Guard, error) {
	return nil, errors.New("bpffsguard: unsupported platform")
}

// Mode describes the active enforcement.
func (g *Guard) Mode() string { return "none" }

// Close is a no-op.
func (g *Guard) Close() error { return nil }
