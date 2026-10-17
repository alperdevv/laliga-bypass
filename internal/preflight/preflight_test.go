package preflight_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/monitor"
	"github.com/alperdevv/laliga-bypass/internal/preflight"
)

func server(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func domain(edgeURL, originAddr string) config.Domain {
	return config.Domain{
		Name:      "127.0.0.1",
		Endpoints: []config.Endpoint{{URL: edgeURL + "/", ExpectedStatus: []int{200, 301, 302}, Timeout: 2 * time.Second}},
		Origin:    config.Origin{Address: originAddr},
	}
}

func addr(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func messages(f []preflight.Finding) string {
	var parts []string
	for _, x := range f {
		parts = append(parts, string(x.Level)+": "+x.Message)
	}
	return strings.Join(parts, " | ")
}

func TestHealthySetupHasNoFindings(t *testing.T) {
	edge, origin := server(t, ok), server(t, ok)
	f := preflight.Check(context.Background(), &monitor.Checker{}, domain(edge.URL, addr(origin)))
	if len(f) != 0 {
		t.Fatal(messages(f))
	}
}

func TestCloudflareAccessIsAnError(t *testing.T) {
	edge := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://team.cloudflareaccess.com/cdn-cgi/access/login/app.example.com", http.StatusFound)
	})
	origin := server(t, ok)
	f := preflight.Check(context.Background(), &monitor.Checker{}, domain(edge.URL, addr(origin)))
	if !preflight.HasErrors(f) || !strings.Contains(messages(f), "Cloudflare Access") {
		t.Fatal(messages(f))
	}
}

func TestRedirectOnlyInCloudflareIsAnError(t *testing.T) {
	edge := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
	})
	origin := server(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	f := preflight.Check(context.Background(), &monitor.Checker{}, domain(edge.URL, addr(origin)))
	if !preflight.HasErrors(f) || !strings.Contains(messages(f), "redirect lives in Cloudflare") {
		t.Fatal(messages(f))
	}
}

func TestUntrustedOriginCertificateIsAnError(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(ok))
	defer origin.Close()
	d := config.Domain{
		Name:      "example.invalid",
		Endpoints: []config.Endpoint{{URL: "https://shop.example.invalid/", ExpectedStatus: []int{200}, Timeout: 2 * time.Second}},
		Origin:    config.Origin{Address: origin.Listener.Addr().String(), InsecureSkipVerify: true},
	}
	f := preflight.Check(context.Background(), &monitor.Checker{}, d)
	if !preflight.HasErrors(f) || !strings.Contains(messages(f), "certificate") {
		t.Fatal(messages(f))
	}
}

func TestUnreachableOriginIsAnError(t *testing.T) {
	edge := server(t, ok)
	f := preflight.Check(context.Background(), &monitor.Checker{}, domain(edge.URL, "127.0.0.1:1"))
	if !preflight.HasErrors(f) || !strings.Contains(messages(f), "origin not reachable") {
		t.Fatal(messages(f))
	}
}
