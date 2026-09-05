// Package sensor loads trapline's compiled BPF program, attaches its probes,
// and turns ring buffer records into event.Event values on a channel.
package sensor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/justinmreynolds93-afk/trapline/internal/event"
)

type Sensor struct {
	objs    TraplineObjects
	links   []link.Link
	reader  *ringbuf.Reader
}

// Open loads the BPF program into the kernel and attaches every probe.
// Requires root (or CAP_BPF + CAP_PERFMON, in practice root is simplest).
func Open() (*Sensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs TraplineObjects
	if err := LoadTraplineObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	s := &Sensor{objs: objs}

	attach := []struct {
		name string
		fn   func() (link.Link, error)
	}{
		{"tracepoint sched/sched_process_exec", func() (link.Link, error) {
			return link.Tracepoint("sched", "sched_process_exec", objs.TpSchedProcessExec, nil)
		}},
		{"kprobe tcp_v4_connect", func() (link.Link, error) {
			return link.Kprobe("tcp_v4_connect", objs.KpTcpV4Connect, nil)
		}},
		{"kretprobe tcp_v4_connect", func() (link.Link, error) {
			return link.Kretprobe("tcp_v4_connect", objs.KrpTcpV4Connect, nil)
		}},
		{"tracepoint syscalls/sys_enter_openat", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_openat", objs.TpSysEnterOpenat, nil)
		}},
	}

	for _, a := range attach {
		l, err := a.fn()
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach %s: %w", a.name, err)
		}
		s.links = append(s.links, l)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}
	s.reader = reader

	return s, nil
}

// Run blocks, decoding ring buffer records and sending them to out, until
// Close is called (which unblocks the reader with ringbuf.ErrClosed) or the
// reader hits an unrecoverable error.
func (s *Sensor) Run(out chan<- event.Event) error {
	for {
		record, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		var raw TraplineEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue // truncated/corrupt record; skip rather than crash the loop
		}
		out <- decode(raw)
	}
}

func (s *Sensor) Close() error {
	if s.reader != nil {
		_ = s.reader.Close()
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	return s.objs.Close()
}

func decode(raw TraplineEvent) event.Event {
	e := event.Event{
		Type:  event.Type(raw.Type),
		PID:   raw.Pid,
		PPID:  raw.Ppid,
		UID:   raw.Uid,
		Comm:  event.CString(raw.Comm[:]),
		PComm: event.CString(raw.Pcomm[:]),
	}
	// raw.TimestampNs is CLOCK_BOOTTIME-relative (from bpf_ktime_get_ns),
	// useful for precise cross-CPU event ordering that this version doesn't
	// yet do; wall time is stamped here instead, at decode time, which is
	// accurate enough given ring buffer delivery latency is sub-millisecond.
	e.Timestamp = time.Now()

	switch e.Type {
	case event.Exec:
		e.Filename = event.CString(raw.Filename[:])
		e.Argv = event.Argv(raw.Argv[:])
	case event.Connect:
		// daddr/dport are __be32/__be16 in the kernel (network byte order),
		// copied byte-for-byte into the struct; binary.Read above decoded
		// the whole struct as little-endian, which is right for every
		// other field but silently byte-swaps these two. Reverse that swap
		// to recover the true value. sport comes from sk->__sk_common.skc_num,
		// which the kernel deliberately keeps in HOST byte order (unlike
		// every other port/address field in sock_common) — no swap needed.
		e.DestIP = be32ToIP(raw.Daddr)
		e.DestPort = bits.ReverseBytes16(raw.Dport)
		e.SrcPort = raw.Sport
	case event.Open:
		e.Filename = event.CString(raw.Filename[:])
		e.OpenFlags = raw.OpenFlags
	}
	return e
}

// be32ToIP recovers the original 4 network-order octets. binary.Read decoded
// them as a little-endian uint32 (swapping them once); encoding them back as
// little-endian is a second swap that cancels the first, leaving the true
// dotted-decimal byte order net.IP expects.
func be32ToIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IP(b)
}
