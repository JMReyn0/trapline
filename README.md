# trapline

A small runtime security sensor built on eBPF: watches process exec,
outbound TCP connects, and sensitive file writes system-wide, and decides
what's suspicious via a declarative YAML rule file — not by recompiling
anything. Written to prove the detections actually fire, not just describe
them: [`test/e2e`](test/e2e/e2e_test.go) loads the real BPF program into a
real kernel and throws real subprocesses at it.

![ci](https://github.com/JMReyn0/trapline/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/badge/license-MIT-blue)
![go](https://img.shields.io/badge/go-%E2%89%A51.25-00ADD8)

## What it watches

Three probes, one ring buffer:

| Event     | Hook point                                      | Captures                                             |
|-----------|--------------------------------------------------|-------------------------------------------------------|
| `exec`    | `sched_process_exec` tracepoint                  | pid/ppid/uid, comm + parent comm, exe path, best-effort argv |
| `connect` | `tcp_v4_connect` kprobe + kretprobe              | pid/comm, destination IP:port, source port             |
| `open`    | `sys_enter_openat` tracepoint (write-mode only)  | pid/comm, opened path, open flags                      |

The kernel side does almost no filtering (just "was this a write-mode
open") and no path/comm/port allowlisting at all — deciding what's
*suspicious* is entirely a userspace, data-driven decision. That's
deliberate: it mirrors how a SIEM works (ingest broadly, detect narrowly)
rather than baking judgment calls into C code you'd need to recompile to
change.

## Detection is data

[`rules/default.yaml`](rules/default.yaml) ships seven rules as an example:
a shell spawned from a network-facing service, a process executing from
`/tmp`, a command line matching a reverse-shell one-liner, an unexpected
root exec, a connection to a commonly-abused port, a write to `/etc/passwd`-
style files, and a write to an `authorized_keys` file. Each rule is a set of
clauses, ANDed together; a list-valued clause matches on any one value:

```yaml
- id: shell-from-network-service
  severity: high
  description: A shell was spawned from a network-facing service process
  match:
    event: exec
    comm: [sh, bash, dash, ash]
    parent_comm: [nginx, apache2, httpd, sshd, mysqld, php-fpm, redis-server]

- id: reverse-shell-argv
  severity: critical
  description: Command line matches a classic reverse-shell one-liner pattern
  match:
    event: exec
    argv_contains: ["/dev/tcp/", "-e /bin/sh", "nc -e", "bash -i"]
```

Available clauses: `comm`, `parent_comm`, `parent_comm_not`, `filename_prefix`,
`filename_suffix`, `filename`, `argv_contains`, `dest_port`, `uid`. Bring
your own file, point `-rules` at it — no rebuild needed.

## Install & run

```bash
go build -o bin/trapline ./cmd/trapline
sudo ./bin/trapline -rules ./rules/default.yaml -verbose
```

Needs root (or `CAP_BPF`+`CAP_PERFMON`) to load BPF programs, and a kernel
with BTF (`/sys/kernel/btf/vmlinux` present — true of any mainstream distro
kernel from the last few years, and of WSL2's kernel too, which is what this
was developed against). Alerts print as newline-delimited JSON on stdout:

```json
{"time":"...","rule_id":"reverse-shell-argv","severity":"critical","description":"...","event":{"Type":1,"PID":1094,"Comm":"sh","PComm":"bash","Filename":"/usr/bin/sh","Argv":"sh -c true /dev/tcp/127.0.0.1/4444"},"username":"root"}
```

## Architecture

```
kernel:  sched_process_exec tp     tcp_v4_connect k[ret]probe    sys_enter_openat tp
              │                            │                            │
              └────────────────────────────┼────────────────────────────┘
                                            ▼
                              one BPF_MAP_TYPE_RINGBUF
                                            │
userspace:                          ring buffer reader
                                            │
                              decode → internal/event.Event
                                            │
                              internal/rules.Engine.Evaluate
                                    (rules/default.yaml)
                                            │
                              alert.New (resolves exe path + username,
                                only for events that actually matched)
                                            │
                                    JSON on stdout
```

## Building this required getting a few real things right

- **BTF pruning.** `struct event` is only ever referenced through local
  pointers in the C probes, and clang's BPF backend prunes BTF to what's
  reachable from global scope — `bpf2go -type event` couldn't find it until
  a [dummy global pointer](bpf/trapline.bpf.c) rooted the type. Standard
  cilium/ebpf gotcha, not obvious until you hit it.
- **Two different "byte order" bugs, in opposite directions.** `daddr`/
  `dport` are `__be32`/`__be16` (genuinely network byte order) but arrive
  already decoded once (incorrectly) as little-endian by `binary.Read`;
  recovering the true value needs an explicit un-swap
  ([`internal/sensor/sensor.go`](internal/sensor/sensor.go)). `sport` comes
  from `sk->__sk_common.skc_num`, which the kernel deliberately keeps in
  *host* byte order unlike every neighboring field in that struct — applying
  the same "fix" there would have been wrong. Caught by checking the actual
  kernel source semantics, not by guessing.
- **A refused connection still needs to be captured.** `tcp_v4_connect`
  returns success as soon as the SYN is queued; `ECONNREFUSED` is discovered
  later and separately by the caller. Confirmed by hand (dialing a closed
  local port) before relying on it in `suspicious-outbound-port` or its test.
- **PID namespaces are real, even on a dev laptop.** The first version of
  the e2e tests matched alerts by comparing `os.Getpid()` / `cmd.Process.Pid`
  against the sensor's reported PID — and two of six failed, consistently,
  with wildly different numbers on each side. `bpf_get_current_pid_tgid()`
  reports the *root* PID namespace by design (correct, and consistent with
  this project's host-only scope — see below); this WSL2/systemd environment
  runs `go test` in a nested namespace, so the two numbers were never going
  to match. Fixed by asserting on namespace-independent facts instead (argv
  content, `comm`, exact paths) — which is also just a better way to write
  these tests regardless of environment.

## Testing

```bash
go test ./...                          # rule engine, no root/kernel needed
sudo go test -tags e2e -v ./test/e2e/... # loads the real sensor, needs root
```

The e2e suite starts the actual compiled BPF program against the running
kernel, then for each shipped rule: creates the exact condition it's meant
to catch (copies a binary into `/tmp` and execs it, execs a command line
containing `/dev/tcp/...`, opens `/etc/passwd` O_RDWR without writing a
single byte, execs a renamed-to-`nginx` binary that spawns a shell, dials a
closed local port) and asserts the matching alert actually appears. CI's
`e2e` job goes a step further: it installs a full clang/bpftool toolchain
and **regenerates `vmlinux.h` and the compiled BPF object from that runner's
own kernel** before running the suite — proving the CO-RE program is
genuinely portable to a kernel it was never built against, not just that it
works on the one machine it was written on.

## What this doesn't do

- **Host-only, not container-aware.** `bpf_get_current_pid_tgid()` reports
  the root PID namespace; an alert's PID is meaningful on the host but isn't
  resolved back to a specific container. No cgroup/namespace correlation, no
  Docker/K8s API lookups. (Scoped deliberately this way — see the "PID
  namespaces" note above for why that surfaced during testing anyway.)
- **IPv4 only.** The connect probe hooks `tcp_v4_connect`; there's no
  `tcp_v6_connect` counterpart yet.
- **argv capture is best-effort, not a parser.** It reads a fixed-size
  window from `task->mm->arg_start`, which is genuinely correct at the
  instant `sched_process_exec` fires, but a short argv can run into
  adjacent environment bytes past `arg_end`, and a long one is silently
  truncated. Fine for substring-style detections; not a real argument list.
- **No cross-event correlation.** Every rule matches one event in
  isolation. Real EDRs detect *sequences* ("this process wrote a file, then
  five seconds later executed it"); trapline doesn't track state across
  events, so that class of detection isn't expressible here.
- **No output integrations.** Alerts are newline-delimited JSON on stdout.
  Shipping them to Elasticsearch, a SIEM, or anywhere else is left to
  whatever you pipe stdout into.

## License

[MIT](LICENSE)
