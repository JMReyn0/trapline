# Changelog

## 0.1.0

Initial release.

- eBPF sensor (Go + `cilium/ebpf`, CO-RE via a committed `vmlinux.h`) hooking
  `sched_process_exec`, `tcp_v4_connect` (kprobe+kretprobe), and
  `sys_enter_openat` (write-mode only) into one ring buffer.
- Declarative YAML rule engine (`internal/rules`) with `comm`, `parent_comm`,
  `parent_comm_not`, `filename_prefix`, `filename_suffix`, `filename`,
  `argv_contains`, `dest_port`, and `uid` clauses.
- Seven shipped detections in `rules/default.yaml`: shell from a
  network-facing service, exec from a temp directory, reverse-shell argv
  patterns, unexpected root exec, connections to commonly-abused ports,
  sensitive system file writes, and `authorized_keys` writes.
- CLI (`cmd/trapline`) printing newline-delimited JSON alerts, enriched with
  resolved exe path and username per alert (not per event).
- Unit tests for the rule engine; an e2e suite that loads the real BPF
  program and fires real subprocesses at each shipped rule.
- CI: a toolchain-free `build` job using committed bpf2go artifacts, and an
  `e2e` job that regenerates the BPF bindings from the runner's own kernel
  before running the privileged e2e suite — proving CO-RE portability, not
  just a single-kernel build.
