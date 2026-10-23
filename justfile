# justfile
set shell := ["bash", "-cu"]

generate:
    cd internal/gen && go generate ./...

build: generate
    mkdir -p build && VERSION=$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev") && go build -ldflags "-X github.com/nipunattri1/xdp-firewall/cmd.version=$VERSION -s -w" -o build/edgewall .

build-release: generate
    mkdir -p build && VERSION=$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev") && go build -ldflags "-X github.com/nipunattri1/xdp-firewall/cmd.version=$VERSION -s -w" -o build/edgewall .

clean:
    rm -rf build internal/gen/*_bpfel.go internal/gen/*_bpfeb.go internal/gen/*.o

fmt:
    gofmt -w .

test:
    go test -count=1 ./...

version:
    @git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev"