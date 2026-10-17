package state_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/state"
)

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := state.Store{Path: filepath.Join(dir, "state.json")}
	now := time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)

	st, err := store.Load()
	if err != nil || len(st.Domains) != 0 {
		t.Fatalf("missing file must load empty state: %v %v", st, err)
	}
	ds := st.Domain("example.com", now)
	ds.SetMode(state.ModeContingency, now)
	ds.Changes["rec"] = &state.RecordChange{ZoneID: "z", RecordID: "rec", Status: state.ChangeApplied, Original: state.Snapshot{Proxied: true}}
	if err := store.Save(st, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file permissions: %v %v", info, err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.Domains["example.com"]
	if got.Mode != state.ModeContingency || len(got.Pending()) != 1 || !got.Changes["rec"].Original.Proxied {
		t.Fatalf("%+v", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "state.json" {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
}

func TestCorruptStateIsNotSilentlyReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (state.Store{Path: path}).Load(); err == nil {
		t.Fatal("corrupt state must be an error")
	}
}

func TestLockIsExclusive(t *testing.T) {
	store := state.Store{Path: filepath.Join(t.TempDir(), "state.json")}
	unlock, err := store.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Lock(); err == nil {
		t.Fatal("second lock must fail")
	}
	unlock()
	unlock2, err := store.Lock()
	if err != nil {
		t.Fatal("lock must be reusable after release:", err)
	}
	unlock2()
}
