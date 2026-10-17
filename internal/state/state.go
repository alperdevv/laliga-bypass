package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const Version = 1

type Mode string

const (
	ModeNormal      Mode = "normal"
	ModeContingency Mode = "contingency"
	ModeRecovery    Mode = "recovery"
)

type ChangeStatus string

const (
	ChangeApplied  ChangeStatus = "applied"
	ChangeRestored ChangeStatus = "restored"
	ChangeReleased ChangeStatus = "released"
)

type Snapshot struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Content    string    `json:"content"`
	Proxied    bool      `json:"proxied"`
	TTL        int       `json:"ttl"`
	ModifiedOn time.Time `json:"modified_on"`
}

type RecordChange struct {
	ZoneID    string       `json:"zone_id"`
	RecordID  string       `json:"record_id"`
	Original  Snapshot     `json:"original"`
	Applied   Snapshot     `json:"applied"`
	Status    ChangeStatus `json:"status"`
	Simulated bool         `json:"simulated"`
	ChangedAt time.Time    `json:"changed_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	Note      string       `json:"note,omitempty"`
}

type DomainState struct {
	Mode                 Mode       `json:"mode"`
	ModeSince            time.Time  `json:"mode_since"`
	LastChange           time.Time  `json:"last_change"`
	ConsecutiveConfirmed int        `json:"consecutive_confirmed"`
	ClearSince           *time.Time `json:"clear_since,omitempty"`
	EdgeIPs              []string   `json:"edge_ips,omitempty"`
	ActivatedAt          time.Time  `json:"activated_at"`
	RestoredAt           time.Time  `json:"restored_at"`
	Simulated            bool       `json:"simulated"`
	ManualHoldUntil      time.Time  `json:"manual_hold_until"`

	LastVerdict string    `json:"last_verdict,omitempty"`
	LastReasons []string  `json:"last_reasons,omitempty"`
	LastCheck   time.Time `json:"last_check"`

	Alerted map[string]bool          `json:"alerted,omitempty"`
	Changes map[string]*RecordChange `json:"changes,omitempty"`
}

func (d *DomainState) Pending() []*RecordChange {
	var out []*RecordChange
	for _, c := range d.Changes {
		if c.Status == ChangeApplied {
			out = append(out, c)
		}
	}
	return out
}

func (d *DomainState) SetMode(m Mode, now time.Time) {
	if d.Mode != m {
		d.Mode = m
		d.ModeSince = now
	}
}

type State struct {
	Version   int                     `json:"version"`
	UpdatedAt time.Time               `json:"updated_at"`
	Domains   map[string]*DomainState `json:"domains"`
}

func New() *State { return &State{Version: Version, Domains: map[string]*DomainState{}} }

func (s *State) Domain(name string, now time.Time) *DomainState {
	d, ok := s.Domains[name]
	if !ok {
		d = &DomainState{Mode: ModeNormal, ModeSince: now}
		s.Domains[name] = d
	}
	if d.Changes == nil {
		d.Changes = map[string]*RecordChange{}
	}
	if d.Alerted == nil {
		d.Alerted = map[string]bool{}
	}
	return d
}

func (s *State) Clone() *State {
	out := New()
	data, err := json.Marshal(s)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, out)
	return out
}

func (s *State) Fingerprint() string {
	cp := *s
	cp.UpdatedAt = time.Time{}
	data, _ := json.Marshal(&cp)
	return string(data)
}

type Store struct {
	Path string
}

func (s Store) Load() (*State, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state %s: %w", s.Path, err)
	}
	st := New()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("state file %s is corrupt (inspect it manually, it will not be overwritten): %w", s.Path, err)
	}
	if st.Version != Version {
		return nil, fmt.Errorf("state file %s has unsupported version %d", s.Path, st.Version)
	}
	if st.Domains == nil {
		st.Domains = map[string]*DomainState{}
	}
	return st, nil
}

func (s Store) Save(st *State, now time.Time) error {
	st.Version = Version
	st.UpdatedAt = now
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return fmt.Errorf("creating temporary state file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("replacing state: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func (s Store) Lock() (func(), error) {
	f, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("state %s is locked by another process (is the service still running?): %w", s.Path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
