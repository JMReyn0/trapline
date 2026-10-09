//go:build linux && e2e

// Package e2e loads the real BPF program into a real kernel and fires real
// subprocesses at it -- no mocks. Requires root (or CAP_BPF+CAP_PERFMON):
//
//	sudo go test -tags e2e ./test/e2e/...
package e2e

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JMReyn0/trapline/internal/alert"
	"github.com/JMReyn0/trapline/internal/event"
	"github.com/JMReyn0/trapline/internal/rules"
	"github.com/JMReyn0/trapline/internal/sensor"
)

var (
	alertsMu sync.Mutex
	alerts   []alert.Alert
)

func recordedAlerts() []alert.Alert {
	alertsMu.Lock()
	defer alertsMu.Unlock()
	out := make([]alert.Alert, len(alerts))
	copy(out, alerts)
	return out
}

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		os.Stderr.WriteString("test/e2e requires root (it loads real BPF programs) -- run under sudo\n")
		os.Exit(1)
	}

	sen, err := sensor.Open()
	if err != nil {
		os.Stderr.WriteString("opening sensor: " + err.Error() + "\n")
		os.Exit(1)
	}

	// The rules this project actually ships, not a synthetic test set --
	// these tests exist to prove the shipped detections really fire.
	loadedRules, err := rules.Load("../../rules/default.yaml")
	if err != nil {
		os.Stderr.WriteString("loading rules: " + err.Error() + "\n")
		os.Exit(1)
	}
	engine := rules.NewEngine(loadedRules)

	events := make(chan event.Event, 256)
	go func() {
		_ = sen.Run(events)
	}()
	debug := os.Getenv("TRAPLINE_E2E_DEBUG") != ""
	go func() {
		for e := range events {
			if debug {
				os.Stderr.WriteString(e.String() + "\n")
			}
			for _, r := range engine.Evaluate(e) {
				a := alert.New(r, e)
				alertsMu.Lock()
				alerts = append(alerts, a)
				alertsMu.Unlock()
			}
		}
	}()

	code := m.Run()
	_ = sen.Close()
	os.Exit(code)
}

// waitForAlert polls the shared alert log until one matching ruleID and
// match appears, or fails the test after timeout. The sensor observes every
// process on the machine, including the test binary itself and anything
// else running concurrently in CI, so tests match on specifics (a PID, an
// exact path) rather than asserting exact alert counts.
func waitForAlert(t *testing.T, ruleID string, match func(alert.Alert) bool, timeout time.Duration) alert.Alert {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, a := range recordedAlerts() {
			if a.RuleID == ruleID && match(a) {
				return a
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, a := range recordedAlerts() {
		if a.RuleID == ruleID {
			t.Logf("candidate alert that did NOT match: pid=%d filename=%q argv=%q", a.Event.PID, a.Event.Filename, a.Event.Argv)
		}
	}
	t.Fatalf("no alert for rule %q matched within %s (total alerts recorded: %d)", ruleID, timeout, len(recordedAlerts()))
	return alert.Alert{}
}

func TestExecFromTempDir(t *testing.T) {
	data, err := os.ReadFile("/bin/echo")
	if err != nil {
		t.Skipf("/bin/echo not available: %v", err)
	}
	path := t.TempDir() + "/testbin"
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := exec.Command(path, "hello").Run(); err != nil {
		t.Fatal(err)
	}

	waitForAlert(t, "exec-from-temp-dir", func(a alert.Alert) bool {
		return a.Event.Filename == path
	}, 5*time.Second)
}

func TestReverseShellArgv(t *testing.T) {
	// A unique marker port, not one any other test in this suite dials, so a
	// substring match on it can't coincide with unrelated background noise.
	const marker = "/dev/tcp/127.0.0.1/4444"
	cmd := exec.Command("/bin/sh", "-c", "true", marker)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	// Not matched by PID: the sensor's bpf_get_current_pid_tgid() reports
	// the host (root) PID namespace by design (see README "What this
	// doesn't do" -- this is scoped host-only, not namespace-aware), while
	// this WSL2/systemd environment runs `go test` in a nested PID
	// namespace, so cmd.Process.Pid and the sensor's reported PID are two
	// different, both-correct numbers for the same process. Match on the
	// one thing that's namespace-independent: the argv content itself.
	waitForAlert(t, "reverse-shell-argv", func(a alert.Alert) bool {
		return strings.Contains(a.Event.Argv, marker)
	}, 5*time.Second)
}

func TestSensitiveFileWrite(t *testing.T) {
	// O_RDWR only, and closed without writing a single byte -- this proves
	// the *open* is detected, without ever touching the file's content.
	f, err := os.OpenFile("/etc/passwd", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("cannot open /etc/passwd O_RDWR in this environment: %v", err)
	}
	f.Close()

	// Matched by comm, not PID -- see TestReverseShellArgv for why PID
	// isn't a reliable cross-check in this environment. task->comm (16
	// bytes, truncated) is namespace-independent; "e2e.test" is what `go
	// test` names the compiled binary for this package.
	waitForAlert(t, "sensitive-file-write", func(a alert.Alert) bool {
		return a.Event.Filename == "/etc/passwd" && a.Event.Comm == "e2e.test"
	}, 5*time.Second)
}

func TestSSHAuthorizedKeysWrite(t *testing.T) {
	sshDir := t.TempDir() + "/.ssh"
	if err := os.MkdirAll(sshDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := sshDir + "/authorized_keys"
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	waitForAlert(t, "ssh-authorized-keys-write", func(a alert.Alert) bool {
		return a.Event.Filename == path
	}, 5*time.Second)
}

func TestShellFromNetworkService(t *testing.T) {
	data, err := os.ReadFile("/bin/dash")
	if err != nil {
		t.Skipf("/bin/dash not available: %v", err)
	}
	fakeNginx := t.TempDir() + "/nginx"
	if err := os.WriteFile(fakeNginx, data, 0o755); err != nil {
		t.Fatal(err)
	}

	// The fake-"nginx" process execs sh directly as its own child, so sh's
	// ppid/pcomm genuinely resolve to the renamed binary -- not a mock.
	if err := exec.Command(fakeNginx, "-c", "sh -c 'echo hi'").Run(); err != nil {
		t.Fatal(err)
	}

	waitForAlert(t, "shell-from-network-service", func(a alert.Alert) bool {
		return a.Event.PComm == "nginx"
	}, 5*time.Second)
}

func TestSuspiciousOutboundPort(t *testing.T) {
	// Nothing needs to be listening: tcp_v4_connect (what the kprobe pair
	// hooks) returns success as soon as the SYN is queued, regardless of
	// whether the peer later refuses or accepts it -- confirmed by hand
	// against this exact port before this test was written.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:4444", 2*time.Second)
	if err == nil {
		conn.Close()
	}

	waitForAlert(t, "suspicious-outbound-port", func(a alert.Alert) bool {
		return a.Event.DestPort == 4444 && a.Event.DestIP.String() == "127.0.0.1"
	}, 5*time.Second)
}
