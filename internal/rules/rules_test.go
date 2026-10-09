package rules

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/JMReyn0/trapline/internal/event"
)

func TestLoadValidatesEventType(t *testing.T) {
	path := writeRules(t, `
rules:
  - id: bad
    severity: high
    description: x
    match:
      event: nonsense
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown event type, got nil")
	}
}

func TestLoadValidatesSeverity(t *testing.T) {
	path := writeRules(t, `
rules:
  - id: bad
    severity: extreme
    description: x
    match:
      event: exec
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown severity, got nil")
	}
}

func TestLoadRejectsDuplicateIDs(t *testing.T) {
	path := writeRules(t, `
rules:
  - id: dup
    severity: high
    description: x
    match:
      event: exec
  - id: dup
    severity: low
    description: y
    match:
      event: open
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a duplicate rule id, got nil")
	}
}

func TestLoadRejectsMissingID(t *testing.T) {
	path := writeRules(t, `
rules:
  - severity: high
    description: x
    match:
      event: exec
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a missing id, got nil")
	}
}

func TestLoadDefaultRulesFile(t *testing.T) {
	// The file this project actually ships. If this doesn't parse, nothing
	// downstream matters.
	path := filepath.Join("..", "..", "rules", "default.yaml")
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("loading rules/default.yaml: %v", err)
	}
	if len(loaded) == 0 {
		t.Fatal("rules/default.yaml loaded zero rules")
	}
}

func writeRules(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMatchesEventTypeGate(t *testing.T) {
	r := Rule{ID: "r", Severity: SeverityLow, Match: Match{Event: "exec", Comm: []string{"sh"}}}
	if r.Matches(event.Event{Type: event.Open, Comm: "sh"}) {
		t.Error("rule scoped to exec should never match an open event")
	}
	if !r.Matches(event.Event{Type: event.Exec, Comm: "sh"}) {
		t.Error("rule should match an exec event with comm=sh")
	}
}

func TestMatchesCommIsCaseInsensitiveOrList(t *testing.T) {
	r := Rule{ID: "r", Match: Match{Event: "exec", Comm: []string{"bash", "sh"}}}
	if !r.Matches(event.Event{Type: event.Exec, Comm: "SH"}) {
		t.Error("expected case-insensitive match on comm")
	}
	if r.Matches(event.Event{Type: event.Exec, Comm: "zsh"}) {
		t.Error("zsh is not in the comm list, should not match")
	}
}

func TestMatchesParentCommAndParentCommNotCombine(t *testing.T) {
	r := Rule{ID: "r", Match: Match{
		Event:         "exec",
		UID:           []int{0},
		ParentCommNot: []string{"sudo", "systemd"},
	}}
	if r.Matches(event.Event{Type: event.Exec, UID: 0, PComm: "sudo"}) {
		t.Error("parent_comm_not should exclude an allowlisted parent")
	}
	if !r.Matches(event.Event{Type: event.Exec, UID: 0, PComm: "bash"}) {
		t.Error("a root exec from a non-allowlisted parent should match")
	}
	if r.Matches(event.Event{Type: event.Exec, UID: 1000, PComm: "bash"}) {
		t.Error("a non-root exec should not match the uid clause")
	}
}

func TestMatchesFilenamePrefixAndSuffix(t *testing.T) {
	prefixRule := Rule{ID: "r1", Match: Match{Event: "exec", FilenamePrefix: []string{"/tmp/", "/dev/shm/"}}}
	if !prefixRule.Matches(event.Event{Type: event.Exec, Filename: "/tmp/x"}) {
		t.Error("expected /tmp/x to match a /tmp/ prefix rule")
	}
	if prefixRule.Matches(event.Event{Type: event.Exec, Filename: "/usr/bin/x"}) {
		t.Error("/usr/bin/x should not match a /tmp/ prefix rule")
	}

	suffixRule := Rule{ID: "r2", Match: Match{Event: "open", FilenameSuffix: []string{".ssh/authorized_keys"}}}
	if !suffixRule.Matches(event.Event{Type: event.Open, Filename: "/home/alice/.ssh/authorized_keys"}) {
		t.Error("expected a per-user home directory authorized_keys path to match the suffix rule")
	}
	if suffixRule.Matches(event.Event{Type: event.Open, Filename: "/home/alice/notes.txt"}) {
		t.Error("an unrelated file under /home should not match the authorized_keys suffix rule")
	}
}

func TestMatchesArgvContains(t *testing.T) {
	r := Rule{ID: "r", Match: Match{Event: "exec", ArgvContains: []string{"/dev/tcp/", "-e /bin/sh"}}}
	if !r.Matches(event.Event{Type: event.Exec, Argv: "sh -c true /dev/tcp/127.0.0.1/4444"}) {
		t.Error("expected a /dev/tcp/ argv to match")
	}
	if r.Matches(event.Event{Type: event.Exec, Argv: "ls -la"}) {
		t.Error("an unrelated argv should not match")
	}
}

func TestMatchesDestPort(t *testing.T) {
	r := Rule{ID: "r", Match: Match{Event: "connect", DestPort: []int{4444, 1337}}}
	if !r.Matches(event.Event{Type: event.Connect, DestPort: 4444}) {
		t.Error("expected port 4444 to match")
	}
	if r.Matches(event.Event{Type: event.Connect, DestPort: 443}) {
		t.Error("port 443 should not match a rule scoped to 4444/1337")
	}
}

func TestEngineEvaluateReturnsAllMatchingRules(t *testing.T) {
	rulesSet := []Rule{
		{ID: "a", Match: Match{Event: "exec", Comm: []string{"sh"}}},
		{ID: "b", Match: Match{Event: "exec", FilenamePrefix: []string{"/tmp/"}}},
		{ID: "c", Match: Match{Event: "open"}},
	}
	engine := NewEngine(rulesSet)

	hits := engine.Evaluate(event.Event{Type: event.Exec, Comm: "sh", Filename: "/tmp/x"})
	if len(hits) != 2 {
		t.Fatalf("expected 2 matching rules, got %d: %+v", len(hits), hits)
	}

	hits = engine.Evaluate(event.Event{Type: event.Open, Filename: "/etc/passwd"})
	if len(hits) != 1 || hits[0].ID != "c" {
		t.Fatalf("expected only rule c to match an open event, got %+v", hits)
	}
}

func TestMatchesConnectEventWithIPUnaffected(t *testing.T) {
	// Guards against a rule accidentally gating on fields it doesn't declare.
	r := Rule{ID: "r", Match: Match{Event: "connect"}}
	e := event.Event{Type: event.Connect, DestIP: net.ParseIP("10.0.0.1"), DestPort: 9999}
	if !r.Matches(e) {
		t.Error("a rule with no clauses beyond event type should match any connect event")
	}
}
