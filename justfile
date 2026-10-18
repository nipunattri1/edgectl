# justfile
set shell := ["bash", "-cu"]

bpf:
    mkdir -p build
    clang -g -O2 -target bpf -Iinclude -Ibpf -c bpf/firewall.bpf.c -o build/firewall.bpf.o

gen: bpf
    go generate ./...

build: gen
    go build -o build/edgewall ./cmd/edgewall

clean:
    rm -rf build bpf/*_bpfel.go bpf/*_bpfeb.go

fmt:
    gofmt -w .
