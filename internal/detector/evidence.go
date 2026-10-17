package detector

import (
	"time"

	"github.com/alperdevv/laliga-bypass/internal/monitor"
)

type Evidence struct {
	Now    time.Time
	Domain string

	Origin []monitor.CheckResult
	Edge   []monitor.CheckResult

	EdgeIPs []string

	Hayahora   *HayahoraEvidence
	Globalping *GlobalpingEvidence
}

type HayahoraEvidence struct {
	Available  bool                `json:"available"`
	Error      string              `json:"error,omitempty"`
	LastUpdate time.Time           `json:"last_update"`
	CheckedIPs []string            `json:"checked_ips"`
	TrackedIPs []string            `json:"tracked_ips"`
	BlockedBy  map[string][]string `json:"blocked_by,omitempty"`
}

type ProbeRole string

const (
	RoleTarget  ProbeRole = "target"
	RoleControl ProbeRole = "control"
)

type ProbeGroupResult struct {
	Name         string    `json:"name"`
	Role         ProbeRole `json:"role"`
	Probes       int       `json:"probes"`
	OK           int       `json:"ok"`
	Reached      int       `json:"reached"`
	Unreachable  int       `json:"unreachable"`
	Inconclusive int       `json:"inconclusive"`
	ResolvedIPs  []string  `json:"resolved_ips,omitempty"`
	Error        string    `json:"error,omitempty"`
}

func (g ProbeGroupResult) Conclusive() int { return g.OK + g.Reached + g.Unreachable }

func (g ProbeGroupResult) IsUnreachable() bool {
	return g.Unreachable > 0 && g.OK == 0 && g.Reached == 0
}

func (g ProbeGroupResult) IsReachable() bool {
	return g.OK+g.Reached > 0 && g.Unreachable == 0
}

type GlobalpingEvidence struct {
	Available  bool               `json:"available"`
	Error      string             `json:"error,omitempty"`
	Target     string             `json:"target"`
	MeasuredAt time.Time          `json:"measured_at"`
	Groups     []ProbeGroupResult `json:"groups"`
}
