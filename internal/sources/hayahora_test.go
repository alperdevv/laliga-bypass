package sources_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/sources"
)

const feedJSON = `{"lastUpdate":"2026-10-17 16:05:25Z","data":[
 {"ip":"104.16.93.114","isp":"DIGI","description":"Cloudflare","stateChanges":[
   {"timestamp":"2026-10-17 15:00:00Z","state":true},
   {"timestamp":"2026-08-18 16:05:27Z","state":false}]},
 {"ip":"104.16.93.114","isp":"Movistar","description":"Cloudflare","stateChanges":[
   {"timestamp":"2026-08-18 16:05:27Z","state":false},
   {"timestamp":"2026-10-17 15:01:00Z","state":true}]},
 {"ip":"104.16.93.114","isp":"Orange","description":"Cloudflare","stateChanges":[
   {"timestamp":"2026-10-17 15:01:00Z","state":true},
   {"timestamp":"2026-10-17 15:30:00Z","state":false}]},
 {"ip":"172.67.1.1","isp":"Vodafone","description":"Cloudflare","stateChanges":[
   {"timestamp":"2026-09-01 10:00:00Z","state":true}]},
 {"ip":"2a06:98c1:3120::3","isp":"Movistar","description":"Cloudflare","stateChanges":[
   {"timestamp":"2026-10-17 15:00:00Z","state":true}]},
 {"ip":"not-an-ip","isp":"DIGI","stateChanges":[{"timestamp":"2026-10-17 15:00:00Z","state":true}]}
]}`

var feedNow = time.Date(2026, 10, 17, 16, 10, 0, 0, time.UTC)

func parse(t *testing.T) *sources.Feed {
	t.Helper()
	f, err := sources.ParseHayahora(strings.NewReader(feedJSON))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseHayahoraUsesLatestStateRegardlessOfOrder(t *testing.T) {
	f := parse(t)
	if !f.LastUpdate.Equal(time.Date(2026, 10, 17, 16, 5, 25, 0, time.UTC)) {
		t.Fatalf("lastUpdate %v", f.LastUpdate)
	}
	ev := f.Lookup([]string{"104.16.93.114"}, sources.LookupOptions{Now: feedNow})
	got := ev.BlockedBy["104.16.93.114"]
	if strings.Join(got, ",") != "DIGI,Movistar" {
		t.Fatalf("blocked by %v", got)
	}
}

func TestLookupReportsUntrackedIPs(t *testing.T) {
	ev := parse(t).Lookup([]string{"198.51.100.7", "104.16.93.114"}, sources.LookupOptions{Now: feedNow})
	if len(ev.CheckedIPs) != 2 || len(ev.TrackedIPs) != 1 || ev.TrackedIPs[0] != "104.16.93.114" {
		t.Fatalf("%+v", ev)
	}
}

func TestLookupFiltersISPsAndOldBlocks(t *testing.T) {
	f := parse(t)
	ev := f.Lookup([]string{"104.16.93.114"}, sources.LookupOptions{ISPs: []string{"movistar"}, Now: feedNow})
	if strings.Join(ev.BlockedBy["104.16.93.114"], ",") != "Movistar" {
		t.Fatalf("isp filter: %v", ev.BlockedBy)
	}
	ev = f.Lookup([]string{"172.67.1.1"}, sources.LookupOptions{IgnoreOlderThan: 12 * time.Hour, Now: feedNow})
	if len(ev.BlockedBy["172.67.1.1"]) != 0 {
		t.Fatalf("old block not ignored: %v", ev.BlockedBy)
	}
	ev = f.Lookup([]string{"172.67.1.1"}, sources.LookupOptions{Now: feedNow})
	if len(ev.BlockedBy["172.67.1.1"]) != 1 {
		t.Fatalf("block ignored without filter: %v", ev.BlockedBy)
	}
}

func TestLookupNormalizesIPv6(t *testing.T) {
	ev := parse(t).Lookup([]string{"2a06:98c1:3120:0:0:0:0:3"}, sources.LookupOptions{Now: feedNow})
	if len(ev.BlockedBy["2a06:98c1:3120::3"]) != 1 {
		t.Fatalf("%+v", ev)
	}
}

func TestParseHayahoraRejectsUnexpectedFormat(t *testing.T) {
	for _, body := range []string{`{}`, `{"lastUpdate":"x","data":[]}`, `[1,2]`, `{"lastUpdate":"2026-10-17 16:05:25Z"}`} {
		if _, err := sources.ParseHayahora(strings.NewReader(body)); err == nil {
			t.Errorf("expected error for %s", body)
		}
	}
}

func TestHayahoraClientCachesAndUsesETag(t *testing.T) {
	var hits, conditional atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(feedJSON))
	}))
	defer srv.Close()

	clock := feedNow
	h := &sources.Hayahora{URL: srv.URL, RefreshInterval: 5 * time.Minute, Now: func() time.Time { return clock }}
	ctx := context.Background()
	if _, err := h.Get(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Get(ctx); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected cached response, got %d hits", hits.Load())
	}
	clock = clock.Add(6 * time.Minute)
	f, err := h.Get(ctx)
	if err != nil || f == nil {
		t.Fatalf("feed %v err %v", f, err)
	}
	if hits.Load() != 2 || conditional.Load() != 1 {
		t.Fatalf("hits=%d conditional=%d", hits.Load(), conditional.Load())
	}
}

func TestHayahoraClientKeepsLastFeedOnError(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(feedJSON))
	}))
	defer srv.Close()
	clock := feedNow
	h := &sources.Hayahora{URL: srv.URL, RefreshInterval: time.Minute, Now: func() time.Time { return clock }}
	if _, err := h.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	clock = clock.Add(2 * time.Minute)
	f, err := h.Get(context.Background())
	if err == nil || f == nil {
		t.Fatalf("expected previous feed with error, got %v %v", f, err)
	}
}
