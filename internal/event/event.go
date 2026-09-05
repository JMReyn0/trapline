// Package event defines trapline's application-level view of a kernel event,
// decoded from the raw ring buffer struct into something a rule can match
// against without knowing about C char arrays or network byte order.
package event

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Type int

const (
	Exec Type = iota + 1
	Connect
	Open
)

func (t Type) String() string {
	switch t {
	case Exec:
		return "exec"
	case Connect:
		return "connect"
	case Open:
		return "open"
	default:
		return "unknown"
	}
}

// Event is intentionally one flat struct covering all three probe types,
// mirroring the kernel-side design: fields not relevant to a given Type are
// left at their zero value. See rules.Rule for what each Type populates.
type Event struct {
	Timestamp time.Time
	Type      Type
	PID       uint32
	PPID      uint32
	UID       uint32
	Comm      string
	PComm     string

	// Exec
	Filename string
	Argv     string

	// Connect
	DestIP   net.IP
	DestPort uint16
	SrcPort  uint16

	// Open
	OpenFlags uint32
}

func (e Event) String() string {
	switch e.Type {
	case Exec:
		return fmt.Sprintf("[exec] pid=%d ppid=%d comm=%s pcomm=%s uid=%d file=%s argv=%q",
			e.PID, e.PPID, e.Comm, e.PComm, e.UID, e.Filename, e.Argv)
	case Connect:
		return fmt.Sprintf("[connect] pid=%d comm=%s pcomm=%s uid=%d dst=%s:%d src_port=%d",
			e.PID, e.Comm, e.PComm, e.UID, e.DestIP, e.DestPort, e.SrcPort)
	case Open:
		return fmt.Sprintf("[open] pid=%d comm=%s pcomm=%s uid=%d file=%s flags=0x%x",
			e.PID, e.Comm, e.PComm, e.UID, e.Filename, e.OpenFlags)
	default:
		return fmt.Sprintf("[unknown type=%d] pid=%d comm=%s", e.Type, e.PID, e.Comm)
	}
}

// CString converts a fixed-size, NUL-terminated (or NUL-padded) C char array
// as produced by bpf2go ([]int8) into a Go string, stopping at the first NUL.
func CString(b []int8) string {
	buf := make([]byte, len(b))
	for i, c := range b {
		if c == 0 {
			return string(buf[:i])
		}
		buf[i] = byte(c)
	}
	return string(buf)
}

// Argv converts the raw, best-effort NUL-separated argv capture into a
// space-joined display string. Not a real argument parser: the capture is a
// fixed-size buffer read from the tail of task->mm->arg_start, so a short
// argv can run into adjacent environment bytes past arg_end, and a long one
// is silently truncated. Good enough for substring-style detections.
func Argv(b []int8) string {
	raw := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			if len(raw) == 0 {
				continue // leading NULs (buffer read before argv populated, or none captured)
			}
			raw = append(raw, ' ')
			continue
		}
		raw = append(raw, byte(c))
	}
	return strings.TrimSpace(string(raw))
}
