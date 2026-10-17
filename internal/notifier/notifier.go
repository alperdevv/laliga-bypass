package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type Level string

const (
	LevelInfo     Level = "info"
	LevelWarning  Level = "warning"
	LevelCritical Level = "critical"
)

type Event struct {
	Time    time.Time      `json:"time"`
	Level   Level          `json:"level"`
	Domain  string         `json:"domain,omitempty"`
	Kind    string         `json:"kind"`
	Message string         `json:"message"`
	Reasons []string       `json:"reasons,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type Notifier interface {
	Notify(ctx context.Context, e Event) error
}

type Log struct{ Logger *slog.Logger }

func (l Log) Notify(ctx context.Context, e Event) error {
	lvl := slog.LevelInfo
	switch e.Level {
	case LevelWarning:
		lvl = slog.LevelWarn
	case LevelCritical:
		lvl = slog.LevelError
	}
	attrs := []slog.Attr{
		slog.String("event", e.Kind),
		slog.String("severity", string(e.Level)),
	}
	if e.Domain != "" {
		attrs = append(attrs, slog.String("domain", e.Domain))
	}
	if len(e.Reasons) > 0 {
		attrs = append(attrs, slog.Any("reasons", e.Reasons))
	}
	for k, v := range e.Fields {
		attrs = append(attrs, slog.Any(k, v))
	}
	l.Logger.LogAttrs(ctx, lvl, e.Message, attrs...)
	return nil
}

type Webhook struct {
	URL      string
	Format   string
	HTTP     *http.Client
	MinLevel Level
}

func (w Webhook) Notify(ctx context.Context, e Event) error {
	if levelRank(e.Level) < levelRank(w.MinLevel) {
		return nil
	}
	text := fmt.Sprintf("[laliga-guard][%s] %s: %s", e.Level, e.Domain, e.Message)
	var payload any
	switch w.Format {
	case "slack":
		payload = map[string]string{"text": text}
	case "discord":
		payload = map[string]string{"content": text}
	default:
		payload = struct {
			Text string `json:"text"`
			Event
		}{text, e}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("webhook: invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	client := w.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("webhook: network error while sending alert")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

func levelRank(l Level) int {
	switch l {
	case LevelCritical:
		return 2
	case LevelWarning:
		return 1
	default:
		return 0
	}
}

type Multi struct {
	Notifiers []Notifier
	Logger    *slog.Logger
}

func (m Multi) Notify(ctx context.Context, e Event) error {
	var errs []error
	for _, n := range m.Notifiers {
		if err := n.Notify(ctx, e); err != nil {
			errs = append(errs, err)
			if m.Logger != nil {
				m.Logger.Warn("notification delivery failed", "error", err.Error(), "kind", e.Kind)
			}
		}
	}
	return errors.Join(errs...)
}

type Recorder struct {
	Events []Event
}

func (r *Recorder) Notify(_ context.Context, e Event) error {
	r.Events = append(r.Events, e)
	return nil
}

func (r *Recorder) Kinds() []string {
	out := make([]string, 0, len(r.Events))
	for _, e := range r.Events {
		out = append(out, e.Kind)
	}
	return out
}
