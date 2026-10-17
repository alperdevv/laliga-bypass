package notifier_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alperdevv/laliga-bypass/internal/notifier"
)

func TestWebhookFormatsAndFiltersByLevel(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		bodies = append(bodies, m)
	}))
	defer srv.Close()

	ctx := context.Background()
	for _, format := range []string{"slack", "discord", "generic"} {
		w := notifier.Webhook{URL: srv.URL, Format: format, MinLevel: notifier.LevelWarning}
		if err := w.Notify(ctx, notifier.Event{Level: notifier.LevelInfo, Kind: "x", Message: "ignored"}); err != nil {
			t.Fatal(err)
		}
		if err := w.Notify(ctx, notifier.Event{Level: notifier.LevelCritical, Domain: "example.com", Kind: "contingency_activated", Message: "hello"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 3 {
		t.Fatalf("expected 3 deliveries, got %d", len(bodies))
	}
	if !strings.Contains(bodies[0]["text"].(string), "hello") || !strings.Contains(bodies[1]["content"].(string), "hello") || bodies[2]["kind"] != "contingency_activated" {
		t.Fatalf("payloads %+v", bodies)
	}
}

func TestWebhookErrorsDoNotLeakURL(t *testing.T) {
	w := notifier.Webhook{URL: "http://127.0.0.1:1/secret-token-path", Format: "generic", MinLevel: notifier.LevelInfo}
	err := w.Notify(context.Background(), notifier.Event{Level: notifier.LevelCritical, Message: "x"})
	if err == nil || strings.Contains(err.Error(), "secret-token-path") {
		t.Fatalf("error %v", err)
	}
}

func TestLogNotifierWritesStructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	l := notifier.Log{Logger: slog.New(slog.NewJSONHandler(&buf, nil))}
	_ = l.Notify(context.Background(), notifier.Event{Level: notifier.LevelWarning, Domain: "example.com", Kind: "assessment_changed", Message: "m", Reasons: []string{"r1"}})
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["level"] != "WARN" || line["event"] != "assessment_changed" || line["domain"] != "example.com" {
		t.Fatalf("%v", line)
	}
}

func TestMultiContinuesAfterFailure(t *testing.T) {
	rec := &notifier.Recorder{}
	m := notifier.Multi{Notifiers: []notifier.Notifier{
		notifier.Webhook{URL: "http://127.0.0.1:1/", MinLevel: notifier.LevelInfo},
		rec,
	}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := m.Notify(context.Background(), notifier.Event{Level: notifier.LevelCritical, Kind: "k"}); err == nil {
		t.Fatal("expected aggregated error")
	}
	if len(rec.Events) != 1 {
		t.Fatal("second notifier not called")
	}
}
