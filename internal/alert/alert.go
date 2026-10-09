// Package alert defines what a fired rule produces and how it's written out.
package alert

import (
	"encoding/json"
	"io"
	"time"

	"github.com/JMReyn0/trapline/internal/enrich"
	"github.com/JMReyn0/trapline/internal/event"
	"github.com/JMReyn0/trapline/internal/rules"
)

type Alert struct {
	Time        time.Time      `json:"time"`
	RuleID      string         `json:"rule_id"`
	Severity    rules.Severity `json:"severity"`
	Description string         `json:"description"`
	Event       event.Event    `json:"event"`
	ResolvedExe string         `json:"resolved_exe,omitempty"`
	Username    string         `json:"username"`
}

// New builds an Alert, resolving the acting process's exe path and username.
// Deliberately done here -- once per alert -- rather than on every observed
// event, since it costs a couple of syscalls and most events never alert.
func New(r rules.Rule, e event.Event) Alert {
	return Alert{
		Time:        e.Timestamp,
		RuleID:      r.ID,
		Severity:    r.Severity,
		Description: r.Description,
		Event:       e,
		ResolvedExe: enrich.ExePath(e.PID),
		Username:    enrich.Username(e.UID),
	}
}

// Writer emits alerts as newline-delimited JSON.
type Writer struct {
	enc *json.Encoder
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{enc: json.NewEncoder(w)}
}

func (w *Writer) Write(a Alert) error {
	return w.enc.Encode(a)
}
