// SPDX-License-Identifier: GPL-2.0
//
// trapline's kernel-side sensor. Three probes, one ring buffer:
//   - sched_process_exec tracepoint  -> EVENT_EXEC
//   - tcp_v4_connect kprobe+kretprobe -> EVENT_CONNECT
//   - sys_enter_openat tracepoint     -> EVENT_OPEN
//
// Deliberately does no path/comm/port filtering here beyond a couple of
// flag checks. What counts as suspicious is a userspace (Go) decision, made
// by data-driven rules, not a decision baked into the kernel program --
// mirrors detection-as-data in the rest of this session's projects. See
// README "What this doesn't do" for the tradeoffs that follow from that.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define ARGV_BUF_LEN 128

enum event_type {
	EVENT_EXEC = 1,
	EVENT_CONNECT = 2,
	EVENT_OPEN = 3,
};

// Field order matters: descending size keeps every scalar naturally aligned
// with no compiler-inserted padding, but this is still marked packed so the
// Go-side decode (a plain byte-for-byte struct read) can never silently
// disagree with clang about layout.
struct event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 type;
	__u32 daddr;      // EVENT_CONNECT only, network byte order
	__u32 open_flags; // EVENT_OPEN only
	__u16 dport;      // EVENT_CONNECT only, network byte order
	__u16 sport;      // EVENT_CONNECT only, network byte order
	char comm[TASK_COMM_LEN];
	char pcomm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	char argv[ARGV_BUF_LEN]; // EVENT_EXEC only, raw NUL-separated argv bytes
} __attribute__((packed));

// struct event is otherwise only referenced via local pointers inside the
// probe functions below; clang's BPF backend prunes BTF to what's reachable
// from global scope, so without this dummy var bpf2go's `-type event` can't
// find it to generate the matching Go struct.
struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// Bridges tcp_v4_connect's kprobe (has the sock*) to its kretprobe (has the
// real return code and, by then, the fully-populated ports) -- the sock
// isn't reliably complete until connect() actually returns.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);  // pid_tgid
	__type(value, __u64); // struct sock *
} connect_sockets SEC(".maps");

static __always_inline void fill_common(struct event *e, __u32 type)
{
	struct task_struct *task;

	e->type = type;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	BPF_CORE_READ_STR_INTO(&e->pcomm, task, real_parent, comm);
}

SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct event *e;
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long arg_start;
	unsigned short offset;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_EXEC);

	offset = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + offset);

	// argv/envp live contiguously (NUL-separated) in the new process's
	// stack once exec has replaced task->mm -- true by the time this
	// tracepoint fires. Best-effort, capped at ARGV_BUF_LEN; good enough
	// for substring-style detections (e.g. "-e", "/dev/tcp/"), not a full
	// argument parser.
	task = (struct task_struct *)bpf_get_current_task();
	mm = BPF_CORE_READ(task, mm);
	arg_start = BPF_CORE_READ(mm, arg_start);
	bpf_probe_read_user(&e->argv, sizeof(e->argv), (void *)arg_start);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp_v4_connect, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 skp = (__u64)sk;

	bpf_map_update_elem(&connect_sockets, &pid_tgid, &skp, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(krp_tcp_v4_connect, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *skp;
	struct sock *sk;
	struct event *e;

	skp = bpf_map_lookup_elem(&connect_sockets, &pid_tgid);
	if (!skp)
		return 0;
	sk = (struct sock *)*skp;
	bpf_map_delete_elem(&connect_sockets, &pid_tgid);

	if (ret != 0)
		return 0; // connect() failed or is still in progress (EINPROGRESS)

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_CONNECT);
	e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	const char *filename = (const char *)ctx->args[1];
	int flags = (int)ctx->args[2];

	// O_WRONLY=1, O_RDWR=2 -- low two bits of the access-mode field.
	if ((flags & 0x3) == 0)
		return 0; // read-only open, not interesting to a write-focused sensor

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_OPEN);
	e->open_flags = flags;
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
