package sensor

// Generates trapline_bpfel.go / trapline_bpfel.o from ../../bpf/trapline.bpf.c,
// including a Go-side Trapline{Event,...} struct mirroring the C `struct event`
// (via -type event) so the ring buffer decode can never disagree with what
// clang actually laid out.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event -cc clang -cflags "-O2 -g -Wall" Trapline ../../bpf/trapline.bpf.c
