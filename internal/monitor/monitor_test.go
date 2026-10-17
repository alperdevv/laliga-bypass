package monitor_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/monitor"
)

func endpoint(url string) config.Endpoint {
	return config.Endpoint{URL: url, ExpectedStatus: []int{200, 301}, Timeout: 2 * time.Second}
}

func TestCheckEdgeClassifiesHTTPStatus(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := &monitor.Checker{}
	ctx := context.Background()

	if r := c.CheckEdge(ctx, endpoint(srv.URL+"/")); r.Outcome != monitor.OutcomeOK || r.RemoteIP != "127.0.0.1" {
		t.Fatalf("%+v", r)
	}
	if r := c.CheckEdge(ctx, endpoint(srv.URL+"/redirect")); r.Outcome != monitor.OutcomeOK || r.Status != 301 {
		t.Fatalf("redirects must not be followed: %+v", r)
	}
	status = http.StatusBadGateway
	if r := c.CheckEdge(ctx, endpoint(srv.URL+"/")); r.Outcome != monitor.OutcomeServerError || !r.Outcome.Reachable() {
		t.Fatalf("%+v", r)
	}
	status = http.StatusForbidden
	if r := c.CheckEdge(ctx, endpoint(srv.URL+"/")); r.Outcome != monitor.OutcomeUnexpectedStatus {
		t.Fatalf("%+v", r)
	}
}

func TestCheckEdgeTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	ep := endpoint(srv.URL)
	ep.Timeout = 200 * time.Millisecond
	r := (&monitor.Checker{}).CheckEdge(context.Background(), ep)
	if r.Outcome != monitor.OutcomeTimeout || r.Outcome.Reachable() {
		t.Fatalf("%+v", r)
	}
}

func TestCheckEdgeConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	r := (&monitor.Checker{}).CheckEdge(context.Background(), endpoint("http://"+addr+"/"))
	if r.Outcome != monitor.OutcomeConnError {
		t.Fatalf("%+v", r)
	}
}

func TestCheckOriginDialsOriginKeepingHostAndSNI(t *testing.T) {
	var gotHost, gotSNI string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotSNI = r.TLS.ServerName
		w.WriteHeader(http.StatusOK)
	}))
	srv.StartTLS()
	defer srv.Close()

	c := &monitor.Checker{}
	ep := endpoint("https://www.example.com/health")
	r := c.CheckOrigin(context.Background(), ep, config.Origin{Address: srv.Listener.Addr().String(), InsecureSkipVerify: true})
	if r.Outcome != monitor.OutcomeOK {
		t.Fatalf("%+v", r)
	}
	if gotHost != "www.example.com" || gotSNI != "www.example.com" {
		t.Fatalf("host=%q sni=%q", gotHost, gotSNI)
	}

	r = c.CheckOrigin(context.Background(), ep, config.Origin{Address: srv.Listener.Addr().String()})
	if r.Outcome != monitor.OutcomeTLSError {
		t.Fatalf("untrusted certificate must be a TLS error: %+v", r)
	}
}

func TestResolverReturnsSortedUniqueIPs(t *testing.T) {
	ips, err := monitor.Resolver{}.LookupIPs(context.Background(), "localhost")
	if err != nil {
		t.Skip("no local resolver:", err)
	}
	for i := 1; i < len(ips); i++ {
		if ips[i-1] >= ips[i] {
			t.Fatalf("not sorted/unique: %v", ips)
		}
	}
}
