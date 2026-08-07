CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -g -Wall

all: include/vmlinux.h src/firewall.skel.h build/cli

include/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

build/firewall.bpf.o: src/firewall.bpf.c include/vmlinux.h src/maps.bpf.h include/common.h
	$(CLANG) -g -O2 -target bpf -Iinclude -c $< -o $@

src/firewall.skel.h: build/firewall.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build/cli: user/main.c user/loader.c include/ini.c src/firewall.skel.h
	$(CC) $(CFLAGS) -Iinclude -Isrc user/main.c user/loader.c include/ini.c -lbpf -lelf -lz -o $@

clean:
	rm -rf include/vmlinux.h src/firewall.skel.h build/ user/cli

.PHONY: all clean