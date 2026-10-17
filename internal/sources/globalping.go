package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/detector"
)

type Globalping struct {
	BaseURL      string
	Token        string
	HTTP         *http.Client
	PollInterval time.Duration
	WaitTimeout  time.Duration
	Now          func() time.Time
}

type HTTPMeasurement struct {
	Host           string
	Path           string
	Query          string
	Protocol       string
	Port           int
	ExpectedStatus []int
	Targets        []config.ProbeGroup
	Controls       []config.ProbeGroup
	ExcludeIPs     []string
}

type gpCreateRequest struct {
	Type               string           `json:"type"`
	Target             string           `json:"target"`
	Locations          []gpLocation     `json:"locations"`
	MeasurementOptions gpMeasurementOpt `json:"measurementOptions"`
}

type gpLocation struct {
	Magic string `json:"magic"`
	Limit int    `json:"limit"`
}

type gpMeasurementOpt struct {
	Request  gpRequest `json:"request"`
	Protocol string    `json:"protocol,omitempty"`
	Port     int       `json:"port,omitempty"`
}

type gpRequest struct {
	Method string `json:"method"`
	Path   string `json:"path,omitempty"`
	Query  string `json:"query,omitempty"`
}

type gpCreateResponse struct {
	ID          string `json:"id"`
	ProbesCount int    `json:"probesCount"`
}

type gpMeasurement struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Results []struct {
		Probe struct {
			Country string `json:"country"`
			ASN     int    `json:"asn"`
			Network string `json:"network"`
		} `json:"probe"`
		Result struct {
			Status          string  `json:"status"`
			StatusCode      int     `json:"statusCode"`
			ResolvedAddress *string `json:"resolvedAddress"`
			FailureSource   string  `json:"failureSource"`
		} `json:"result"`
	} `json:"results"`
}

type gpError struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

var ErrRateLimited = errors.New("globalping: rate limit exceeded (HTTP 429)")

func (g *Globalping) MeasureHTTP(ctx context.Context, m HTTPMeasurement) *detector.GlobalpingEvidence {
	ev := &detector.GlobalpingEvidence{Target: m.Host, MeasuredAt: g.now()}
	type job struct {
		group config.ProbeGroup
		role  detector.ProbeRole
	}
	var jobs []job
	for _, t := range m.Targets {
		jobs = append(jobs, job{t, detector.RoleTarget})
	}
	for _, c := range m.Controls {
		jobs = append(jobs, job{c, detector.RoleControl})
	}
	results := make([]detector.ProbeGroupResult, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = g.measureGroup(ctx, m, j.group, j.role)
		}()
	}
	wg.Wait()
	ev.Groups = results

	var errs []string
	for _, r := range results {
		if r.Error != "" {
			errs = append(errs, r.Name+": "+r.Error)
		}
	}
	if len(errs) == len(results) {
		ev.Error = strings.Join(errs, "; ")
		return ev
	}
	ev.Available = true
	if len(errs) > 0 {
		ev.Error = "partial errors: " + strings.Join(errs, "; ")
	}
	return ev
}

func (g *Globalping) measureGroup(ctx context.Context, m HTTPMeasurement, pg config.ProbeGroup, role detector.ProbeRole) detector.ProbeGroupResult {
	out := detector.ProbeGroupResult{Name: pg.Name, Role: role}
	id, err := g.create(ctx, gpCreateRequest{
		Type:      "http",
		Target:    m.Host,
		Locations: []gpLocation{{Magic: pg.Magic, Limit: pg.Limit}},
		MeasurementOptions: gpMeasurementOpt{
			Request:  gpRequest{Method: "GET", Path: m.Path, Query: m.Query},
			Protocol: m.Protocol,
			Port:     m.Port,
		},
	})
	if err != nil {
		out.Error = err.Error()
		return out
	}
	meas, err := g.wait(ctx, id)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for _, r := range meas.Results {
		out.Probes++
		res := r.Result
		if res.ResolvedAddress != nil && *res.ResolvedAddress != "" {
			ip := *res.ResolvedAddress
			if !slices.Contains(out.ResolvedIPs, ip) {
				out.ResolvedIPs = append(out.ResolvedIPs, ip)
			}
			if slices.Contains(m.ExcludeIPs, ip) {
				out.Inconclusive++
				continue
			}
		}
		switch res.Status {
		case "finished":
			if slices.Contains(m.ExpectedStatus, res.StatusCode) {
				out.OK++
			} else {
				out.Reached++
			}
		case "failed":
			if res.FailureSource == "target" || res.FailureSource == "" {
				out.Unreachable++
			} else {
				out.Inconclusive++
			}
		default:
			out.Inconclusive++
		}
	}
	if out.Probes == 0 {
		out.Error = "no probe ran the test"
	}
	return out
}

func (g *Globalping) create(ctx context.Context, body gpCreateRequest) (string, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(g.BaseURL, "/")+"/v1/measurements", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return "", apiError(resp, data)
	}
	var cr gpCreateResponse
	if err := json.Unmarshal(data, &cr); err != nil || cr.ID == "" {
		return "", fmt.Errorf("globalping: unexpected create response (HTTP %d)", resp.StatusCode)
	}
	return cr.ID, nil
}

func (g *Globalping) wait(ctx context.Context, id string) (*gpMeasurement, error) {
	timeout := g.WaitTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	poll := g.PollInterval
	if poll <= 0 {
		poll = time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last *gpMeasurement
	for {
		m, err := g.get(ctx, id)
		if err != nil {
			if last != nil && ctx.Err() != nil {
				return last, nil
			}
			return nil, err
		}
		last = m
		if m.Status != "in-progress" {
			return m, nil
		}
		select {
		case <-ctx.Done():
			return last, nil
		case <-time.After(poll):
		}
	}
}

func (g *Globalping) get(ctx context.Context, id string) (*gpMeasurement, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(g.BaseURL, "/")+"/v1/measurements/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp, data)
	}
	var m gpMeasurement
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("globalping: unexpected measurement %s format: %w", id, err)
	}
	return &m, nil
}

func (g *Globalping) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "github.com/alperdevv/laliga-bypass/1")
	req.Header.Set("Accept", "application/json")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	client := g.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("globalping: %w", err)
	}
	return resp, nil
}

func apiError(resp *http.Response, body []byte) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("%w; resets in %ss", ErrRateLimited, resp.Header.Get("X-RateLimit-Reset"))
	}
	var e gpError
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return fmt.Errorf("globalping: HTTP %d: %s (%s)", resp.StatusCode, e.Error.Message, e.Error.Type)
	}
	return fmt.Errorf("globalping: HTTP %d", resp.StatusCode)
}

func (g *Globalping) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}
