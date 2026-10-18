package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../include -I../../bpf -g -O2" -target native firewall ../../bpf/firewall.bpf.c
