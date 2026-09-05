// Package rules is trapline's detection engine: what counts as suspicious is
// data (a YAML file), not a decision baked into the kernel probes or into Go
// code you'd have to recompile to change.
package rules

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/justinmreynolds93-afk/trapline/internal/event"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Match's clauses are ANDed together; within a list-valued clause, any one
// value matching the event is enough (an OR). Every list is optional --
// an empty/absent list means "don't filter on this."
type Match struct {
	Event          string   `yaml:"event"`
	Comm           []string `yaml:"comm,omitempty"`
	ParentComm     []string `yaml:"parent_comm,omitempty"`
	ParentCommNot  []string `yaml:"parent_comm_not,omitempty"`
	FilenamePrefix []string `yaml:"filename_prefix,omitempty"`
	FilenameSuffix []string `yaml:"filename_suffix,omitempty"`
	Filename       []string `yaml:"filename,omitempty"`
	ArgvContains   []string `yaml:"argv_contains,omitempty"`
	DestPort       []int    `yaml:"dest_port,omitempty"`
	UID            []int    `yaml:"uid,omitempty"`
}

type Rule struct {
	ID          string   `yaml:"id"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Match       Match    `yaml:"match"`
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// Load parses a YAML rule file and validates every rule's event type and
// severity up front, so a typo fails at load time instead of silently never
// matching.
func Load(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse rules file: %w", err)
	}
	seen := make(map[string]bool, len(rf.Rules))
	for i, r := range rf.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rule at index %d has no id", i)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		switch r.Match.Event {
		case "exec", "connect", "open":
		default:
			return nil, fmt.Errorf("rule %q: unknown event type %q", r.ID, r.Match.Event)
		}
		switch r.Severity {
		case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		default:
			return nil, fmt.Errorf("rule %q: unknown severity %q", r.ID, r.Severity)
		}
	}
	return rf.Rules, nil
}

var eventTypeByName = map[string]event.Type{
	"exec":    event.Exec,
	"connect": event.Connect,
	"open":    event.Open,
}

// Matches reports whether e satisfies every clause set on the rule.
func (r Rule) Matches(e event.Event) bool {
	if e.Type != eventTypeByName[r.Match.Event] {
		return false
	}
	m := r.Match

	if len(m.Comm) > 0 && !containsFold(m.Comm, e.Comm) {
		return false
	}
	if len(m.ParentComm) > 0 && !containsFold(m.ParentComm, e.PComm) {
		return false
	}
	if len(m.ParentCommNot) > 0 && containsFold(m.ParentCommNot, e.PComm) {
		return false
	}
	if len(m.FilenamePrefix) > 0 && !hasAnyPrefix(e.Filename, m.FilenamePrefix) {
		return false
	}
	if len(m.FilenameSuffix) > 0 && !hasAnySuffix(e.Filename, m.FilenameSuffix) {
		return false
	}
	if len(m.Filename) > 0 && !containsFold(m.Filename, e.Filename) {
		return false
	}
	if len(m.ArgvContains) > 0 && !containsSubstring(e.Argv, m.ArgvContains) {
		return false
	}
	if len(m.DestPort) > 0 && !containsInt(m.DestPort, int(e.DestPort)) {
		return false
	}
	if len(m.UID) > 0 && !containsInt(m.UID, int(e.UID)) {
		return false
	}
	return true
}

func containsFold(list []string, val string) bool {
	for _, v := range list {
		if strings.EqualFold(v, val) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func containsSubstring(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func containsInt(list []int, val int) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

// Engine evaluates every loaded rule against each event.
type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Evaluate returns every rule that matches e, in load order.
func (en *Engine) Evaluate(e event.Event) []Rule {
	var hits []Rule
	for _, r := range en.rules {
		if r.Matches(e) {
			hits = append(hits, r)
		}
	}
	return hits
}
