.PHONY: generate build lint test e2e run

# Regenerates bpf/vmlinux.h and the bpf2go bindings from THIS machine's own
# kernel BTF. Needs clang, llvm, libbpf-dev, and a bpftool binary on PATH.
# Not required for a normal build -- the generated output is committed so
# `go build` works with nothing but a Go toolchain.
generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	go generate ./...

build:
	go build -o bin/trapline ./cmd/trapline

lint:
	go vet ./...

test:
	go test -count=1 ./...

# Requires root -- loads real BPF programs into the kernel.
e2e:
	go test -tags e2e -v -count=1 ./test/e2e/...

run: build
	./bin/trapline -verbose
