CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -g -Wall

all: include/vmlinux.h bpf/firewall.skel.h build/cli

include/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

build/firewall.bpf.o: bpf/firewall.bpf.c include/vmlinux.h bpf/maps.bpf.h include/common.h
	$(CLANG) -g -O2 -target bpf -Iinclude -Ibpf -c $< -o $@

bpf/firewall.skel.h: build/firewall.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build/cli: user/main.c user/attach.c user/detach.c user/reload.c user/blacklist.c include/ini.c bpf/firewall.skel.h
	$(CC) $(CFLAGS) -Iinclude -Ibpf user/main.c user/attach.c user/detach.c user/reload.c user/blacklist.c include/ini.c -lbpf -lelf -lz -o $@

clean:
	rm -rf include/vmlinux.h bpf/firewall.skel.h build/ user/cli

.PHONY: all clean
