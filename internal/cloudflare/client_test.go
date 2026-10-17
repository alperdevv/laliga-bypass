package cloudflare_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/alperdevv/laliga-bypass/internal/cloudflare"
	"github.com/alperdevv/laliga-bypass/internal/cloudflare/cftest"
)

const (
	token  = "test-token-very-secret"
	zoneID = "zone1"
)

func setup(t *testing.T, dryRun bool) (*cftest.Server, *cloudflare.Client) {
	t.Helper()
	srv := cftest.New(token)
	t.Cleanup(srv.Close)
	srv.AddZone(zoneID, "example.com")
	srv.AddRecord(zoneID, cloudflare.Record{ID: "web", Name: "example.com", Type: "A", Content: "203.0.113.10", Proxied: true, Proxiable: true, TTL: 1})
	srv.AddRecord(zoneID, cloudflare.Record{ID: "mx", Name: "example.com", Type: "MX", Content: "mail.example.com"})
	srv.AddRecord(zoneID, cloudflare.Record{ID: "other", Name: "api.example.com", Type: "A", Content: "203.0.113.11", Proxied: true})
	c, err := cloudflare.New(cloudflare.Options{
		BaseURL:   srv.BaseURL(),
		Token:     token,
		DryRun:    dryRun,
		Allowlist: []cloudflare.RecordRef{{ZoneID: zoneID, RecordID: "web"}, {ZoneID: zoneID, RecordID: "mx"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func TestGetRecordSendsBearerTokenAndParsesRecord(t *testing.T) {
	srv, c := setup(t, false)
	r, err := c.GetRecord(context.Background(), zoneID, "web")
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "example.com" || r.Type != "A" || r.Content != "203.0.113.10" || !r.Proxied || r.ModifiedOn.IsZero() {
		t.Fatalf("unexpected record %+v", r)
	}
	reqs := srv.Requests()
	if len(reqs) != 1 || reqs[0].Method != "GET" || reqs[0].Path != "/client/v4/zones/zone1/dns_records/web" {
		t.Fatalf("unexpected requests %+v", reqs)
	}
}

func TestSetProxiedPatchesOnlyProxiedField(t *testing.T) {
	srv, c := setup(t, false)
	r, err := c.SetProxied(context.Background(), zoneID, "web", "A", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Proxied {
		t.Fatal("record still proxied")
	}
	reqs := srv.Requests()
	if len(reqs) != 1 || reqs[0].Method != "PATCH" || strings.TrimSpace(reqs[0].Body) != `{"proxied":false}` {
		t.Fatalf("unexpected requests %+v", reqs)
	}
	if got := srv.Record(zoneID, "web"); got.Content != "203.0.113.10" || got.Proxied {
		t.Fatalf("server record %+v", got)
	}
}

func TestDryRunNeverSendsWriteRequests(t *testing.T) {
	srv, c := setup(t, true)
	_, err := c.SetProxied(context.Background(), zoneID, "web", "A", false)
	if !errors.Is(err, cloudflare.ErrDryRun) {
		t.Fatalf("expected ErrDryRun, got %v", err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Fatalf("dry run sent %d requests", n)
	}
	if !srv.Record(zoneID, "web").Proxied {
		t.Fatal("record modified in dry run")
	}
}

func TestRecordsOutsideAllowlistAreNeverTouched(t *testing.T) {
	srv, c := setup(t, false)
	ctx := context.Background()
	if _, err := c.SetProxied(ctx, zoneID, "other", "A", false); !errors.Is(err, cloudflare.ErrNotAllowed) {
		t.Fatalf("expected ErrNotAllowed, got %v", err)
	}
	if _, err := c.GetRecord(ctx, zoneID, "other"); !errors.Is(err, cloudflare.ErrNotAllowed) {
		t.Fatalf("expected ErrNotAllowed on read, got %v", err)
	}
	if _, err := c.SetProxied(ctx, "zone2", "web", "A", false); !errors.Is(err, cloudflare.ErrNotAllowed) {
		t.Fatalf("expected ErrNotAllowed for other zone, got %v", err)
	}
	if _, err := c.GetZone(ctx, "zone2"); !errors.Is(err, cloudflare.ErrNotAllowed) {
		t.Fatalf("expected ErrNotAllowed for zone read, got %v", err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Fatalf("sent %d requests for non-allowed records", n)
	}
}

func TestMailRecordsAreRejectedEvenIfAllowlisted(t *testing.T) {
	srv, c := setup(t, false)
	if _, err := c.SetProxied(context.Background(), zoneID, "mx", "MX", false); !errors.Is(err, cloudflare.ErrUnsupportedType) {
		t.Fatalf("expected ErrUnsupportedType, got %v", err)
	}
	if srv.Count("PATCH") != 0 {
		t.Fatal("PATCH sent for MX record")
	}
}

func TestAPIErrorsAreReportedWithoutLeakingToken(t *testing.T) {
	srv, _ := setup(t, false)
	bad, err := cloudflare.New(cloudflare.Options{
		BaseURL:   srv.BaseURL(),
		Token:     "wrong-secret-token",
		Allowlist: []cloudflare.RecordRef{{ZoneID: zoneID, RecordID: "web"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bad.GetRecord(context.Background(), zoneID, "web")
	var apiErr *cloudflare.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("expected 403 APIError, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong-secret-token") {
		t.Fatal("error message leaks the token")
	}
}

func TestMissingRecordReturnsAPIError(t *testing.T) {
	srv := cftest.New(token)
	defer srv.Close()
	c, err := cloudflare.New(cloudflare.Options{BaseURL: srv.BaseURL(), Token: token, Allowlist: []cloudflare.RecordRef{{ZoneID: zoneID, RecordID: "gone"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetRecord(context.Background(), zoneID, "gone")
	var apiErr *cloudflare.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 404 || apiErr.Errors[0].Code != 81044 {
		t.Fatalf("expected 404/81044, got %v", err)
	}
}

func TestNewRequiresTokenAndAllowlist(t *testing.T) {
	if _, err := cloudflare.New(cloudflare.Options{Allowlist: []cloudflare.RecordRef{{ZoneID: "z", RecordID: "r"}}}); err == nil {
		t.Fatal("expected error without token")
	}
	if _, err := cloudflare.New(cloudflare.Options{Token: "x"}); err == nil {
		t.Fatal("expected error without allowlist")
	}
}

func TestGetZone(t *testing.T) {
	_, c := setup(t, false)
	z, err := c.GetZone(context.Background(), zoneID)
	if err != nil || z.Name != "example.com" {
		t.Fatalf("zone %+v err %v", z, err)
	}
}

func TestListerPaginatesZonesAndRecords(t *testing.T) {
	srv := cftest.New(token)
	defer srv.Close()
	for i := range 120 {
		id := fmt.Sprintf("z%03d", i)
		srv.AddZone(id, fmt.Sprintf("site%03d.example", i))
	}
	for i := range 3 {
		srv.AddRecord("z001", cloudflare.Record{ID: fmt.Sprintf("r%d", i), Name: fmt.Sprintf("h%d.site001.example", i), Type: "A", Content: "203.0.113.1", Proxied: true})
	}
	l, err := cloudflare.NewLister(srv.BaseURL(), token, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	zones, err := l.Zones(ctx, "")
	if err != nil || len(zones) != 120 {
		t.Fatalf("zones %d err %v", len(zones), err)
	}
	one, err := l.Zones(ctx, "site007.example")
	if err != nil || len(one) != 1 || one[0].ID != "z007" {
		t.Fatalf("filtered %+v err %v", one, err)
	}
	recs, err := l.Records(ctx, "z001")
	if err != nil || len(recs) != 3 {
		t.Fatalf("records %d err %v", len(recs), err)
	}
	if srv.Count("PATCH") != 0 {
		t.Fatal("lister must be read-only")
	}
}
