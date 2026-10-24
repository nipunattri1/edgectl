package gen

//go:generate go tool bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall" Edgectl ../../bpf/firewall.bpf.c
