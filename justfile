# justfile
set shell := ["bash", "-cu"]

generate:
    cd internal/bpf && go generate ./...

build: generate
    mkdir -p build
    go build -o build/edgewall ./cmd/edgewall

clean:
    rm -rf build internal/bpf/*_bpfel.go internal/bpf/*_bpfeb.go internal/bpf/*.o

fmt:
    gofmt -w .
