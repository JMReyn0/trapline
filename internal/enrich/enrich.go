// Package enrich resolves the extra context worth a syscall or two -- only
// called per-alert, not per-event, since most observed events never alert.
package enrich

import (
	"fmt"
	"os"
	"os/user"
)

// ExePath returns the resolved target of /proc/<pid>/exe, or "" if the
// process has already exited or the path can't be read (e.g. permissions,
// a kernel thread with no exe).
func ExePath(pid uint32) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return path
}

// Username resolves a numeric UID to a username, falling back to the
// numeric UID (as a string) if it isn't in the system's user database.
func Username(uid uint32) string {
	u, err := user.LookupId(fmt.Sprint(uid))
	if err != nil {
		return fmt.Sprint(uid)
	}
	return u.Username
}
