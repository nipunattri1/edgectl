package gen

//go:generate go tool bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall" EdgeWall ../../bpf/firewall.bpf.c
