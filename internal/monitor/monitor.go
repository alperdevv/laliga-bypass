package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"sort"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/config"
)

type Outcome string

const (
	OutcomeOK               Outcome = "ok"
	OutcomeUnexpectedStatus Outcome = "unexpected_status"
	OutcomeServerError      Outcome = "server_error"
	OutcomeTimeout          Outcome = "timeout"
	OutcomeConnError        Outcome = "conn_error"
	OutcomeTLSError         Outcome = "tls_error"
	OutcomeDNSError         Outcome = "dns_error"
)

func (o Outcome) Reachable() bool {
	return o == OutcomeOK || o == OutcomeUnexpectedStatus || o == OutcomeServerError
}

type CheckResult struct {
	URL      string        `json:"url"`
	Via      string        `json:"via"`
	Outcome  Outcome       `json:"outcome"`
	Status   int           `json:"status,omitempty"`
	RemoteIP string        `json:"remote_ip,omitempty"`
	Latency  time.Duration `json:"latency"`
	Error    string        `json:"error,omitempty"`
}

type Checker struct {
	RootCAs *x509.CertPool
}

func (c *Checker) CheckEdge(ctx context.Context, ep config.Endpoint) CheckResult {
	return c.check(ctx, ep, "edge", "", false)
}

func (c *Checker) CheckOrigin(ctx context.Context, ep config.Endpoint, o config.Origin) CheckResult {
	return c.check(ctx, ep, "origin", o.Address, o.InsecureSkipVerify)
}

func (c *Checker) check(ctx context.Context, ep config.Endpoint, via, dialAddr string, insecure bool) CheckResult {
	res := CheckResult{URL: ep.URL, Via: via}
	ctx, cancel := context.WithTimeout(ctx, ep.Timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: ep.Timeout}
	tr := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: ep.Timeout,
		TLSClientConfig: &tls.Config{
			RootCAs:            c.RootCAs,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dialAddr != "" {
				addr = dialAddr
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if a, ok := info.Conn.RemoteAddr().(*net.TCPAddr); ok {
				res.RemoteIP = a.IP.String()
			}
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, ep.URL, nil)
	if err != nil {
		res.Outcome, res.Error = OutcomeConnError, err.Error()
		return res
	}
	req.Header.Set("User-Agent", "github.com/alperdevv/laliga-bypass/1")
	req.Header.Set("Cache-Control", "no-cache")

	start := time.Now()
	resp, err := client.Do(req)
	res.Latency = time.Since(start)
	if err != nil {
		res.Outcome, res.Error = classifyError(ctx, err), err.Error()
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	res.Status = resp.StatusCode
	switch {
	case slices.Contains(ep.ExpectedStatus, resp.StatusCode):
		res.Outcome = OutcomeOK
	case resp.StatusCode >= 500:
		res.Outcome = OutcomeServerError
	default:
		res.Outcome = OutcomeUnexpectedStatus
	}
	return res
}

func classifyError(ctx context.Context, err error) Outcome {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var recErr tls.RecordHeaderError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return OutcomeDNSError
	case errors.As(err, &certErr), errors.As(err, &recErr), errors.As(err, &unknownAuth), errors.As(err, &hostErr):
		return OutcomeTLSError
	case errors.Is(err, context.DeadlineExceeded), ctx.Err() != nil:
		return OutcomeTimeout
	case errors.As(err, &netErr) && netErr.Timeout():
		return OutcomeTimeout
	default:
		return OutcomeConnError
	}
}

type Resolver struct {
	Addr    string
	Timeout time.Duration
}

func (r Resolver) LookupIPs(ctx context.Context, host string) ([]string, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := net.DefaultResolver
	if r.Addr != "" {
		res = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, network, r.Addr)
			},
		}
	}
	addrs, err := res.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		s := a.IP.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}
