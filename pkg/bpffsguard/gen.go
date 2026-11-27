package bpffsguard

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 -type event bpf bpf/bpffsguard.bpf.c -- -I./bpf -O2 -g -Wall -Werror
