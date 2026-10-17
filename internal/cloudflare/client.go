package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

var (
	ErrDryRun          = errors.New("cloudflare: modification blocked by DRY_RUN")
	ErrNotAllowed      = errors.New("cloudflare: record is not in the allowlist")
	ErrUnsupportedType = errors.New("cloudflare: record type is not manageable")
)

type Record struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Content    string    `json:"content"`
	Proxied    bool      `json:"proxied"`
	Proxiable  bool      `json:"proxiable"`
	TTL        int       `json:"ttl"`
	ModifiedOn time.Time `json:"modified_on"`
}

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type RecordRef struct {
	ZoneID   string
	RecordID string
}

type Options struct {
	BaseURL   string
	Token     string
	DryRun    bool
	Allowlist []RecordRef
	HTTP      *http.Client
}

type Client struct {
	base   string
	token  string
	dryRun bool
	allow  map[RecordRef]bool
	zones  map[string]bool
	http   *http.Client
}

func New(o Options) (*Client, error) {
	if strings.TrimSpace(o.Token) == "" {
		return nil, errors.New("cloudflare: empty CF_API_TOKEN")
	}
	if len(o.Allowlist) == 0 {
		return nil, errors.New("cloudflare: empty allowlist")
	}
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	if _, err := url.ParseRequestURI(base); err != nil {
		return nil, fmt.Errorf("cloudflare: invalid base URL: %w", err)
	}
	c := &Client{
		base:   strings.TrimRight(base, "/"),
		token:  o.Token,
		dryRun: o.DryRun,
		allow:  map[RecordRef]bool{},
		zones:  map[string]bool{},
		http:   o.HTTP,
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 20 * time.Second}
	}
	for _, r := range o.Allowlist {
		c.allow[r] = true
		c.zones[r.ZoneID] = true
	}
	return c, nil
}

func (c *Client) DryRun() bool { return c.dryRun }

func (c *Client) GetZone(ctx context.Context, zoneID string) (Zone, error) {
	var z Zone
	if !c.zones[zoneID] {
		return z, fmt.Errorf("%w: zone %s", ErrNotAllowed, zoneID)
	}
	err := c.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID), nil, &z)
	return z, err
}

func (c *Client) GetRecord(ctx context.Context, zoneID, recordID string) (Record, error) {
	var r Record
	if !c.allow[RecordRef{zoneID, recordID}] {
		return r, fmt.Errorf("%w: %s/%s", ErrNotAllowed, zoneID, recordID)
	}
	if err := c.call(ctx, http.MethodGet, recordPath(zoneID, recordID), nil, &r); err != nil {
		return r, err
	}
	if r.ID != recordID {
		return r, fmt.Errorf("cloudflare: API returned record %q instead of %q", r.ID, recordID)
	}
	return r, nil
}

func (c *Client) SetProxied(ctx context.Context, zoneID, recordID, recordType string, proxied bool) (Record, error) {
	var r Record
	if c.dryRun {
		return r, ErrDryRun
	}
	if !c.allow[RecordRef{zoneID, recordID}] {
		return r, fmt.Errorf("%w: %s/%s", ErrNotAllowed, zoneID, recordID)
	}
	switch strings.ToUpper(recordType) {
	case "A", "AAAA", "CNAME":
	default:
		return r, fmt.Errorf("%w: %s", ErrUnsupportedType, recordType)
	}
	if err := c.call(ctx, http.MethodPatch, recordPath(zoneID, recordID), map[string]bool{"proxied": proxied}, &r); err != nil {
		return r, err
	}
	if r.ID != recordID || r.Proxied != proxied {
		return r, fmt.Errorf("cloudflare: unexpected PATCH response (id=%q proxied=%v)", r.ID, r.Proxied)
	}
	return r, nil
}

func recordPath(zoneID, recordID string) string {
	return "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(recordID)
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []APIMessage    `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo resultInfo      `json:"result_info"`
}

type resultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

type APIMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type APIError struct {
	Method string
	Path   string
	Status int
	Errors []APIMessage
}

func (e *APIError) Error() string {
	msgs := make([]string, 0, len(e.Errors))
	for _, m := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%d: %s", m.Code, m.Message))
	}
	return fmt.Sprintf("cloudflare: %s %s -> HTTP %d %s", e.Method, e.Path, e.Status, strings.Join(msgs, "; "))
}

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	_, err := doCall(ctx, c.http, c.base, c.token, method, path, in, out)
	return err
}

func doCall(ctx context.Context, hc *http.Client, base, token, method, path string, in, out any) (resultInfo, error) {
	var info resultInfo
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return info, err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return info, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "laliga-guard/1")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return info, fmt.Errorf("cloudflare: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return info, fmt.Errorf("cloudflare: reading %s %s response: %w", method, path, err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return info, &APIError{Method: method, Path: path, Status: resp.StatusCode, Errors: []APIMessage{{Message: "non-JSON response"}}}
	}
	if resp.StatusCode/100 != 2 || !env.Success {
		return info, &APIError{Method: method, Path: path, Status: resp.StatusCode, Errors: env.Errors}
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return info, fmt.Errorf("cloudflare: unexpected result for %s %s: %w", method, path, err)
		}
	}
	return env.ResultInfo, nil
}
