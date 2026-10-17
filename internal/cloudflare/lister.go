package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Lister struct {
	base  string
	token string
	http  *http.Client
}

func NewLister(baseURL, token string, hc *http.Client) (*Lister, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("cloudflare: empty CF_API_TOKEN")
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Lister{base: strings.TrimRight(baseURL, "/"), token: token, http: hc}, nil
}

func (l *Lister) Zone(ctx context.Context, zoneID string) (Zone, error) {
	var z Zone
	_, err := doCall(ctx, l.http, l.base, l.token, http.MethodGet, "/zones/"+url.PathEscape(zoneID), nil, &z)
	return z, err
}

func (l *Lister) Zones(ctx context.Context, name string) ([]Zone, error) {
	q := url.Values{"per_page": {"50"}}
	if name != "" {
		q.Set("name", name)
	}
	var all []Zone
	err := l.paginate(ctx, "/zones", q, func() any { return &[]Zone{} }, func(v any) {
		all = append(all, *v.(*[]Zone)...)
	})
	return all, err
}

func (l *Lister) Records(ctx context.Context, zoneID string) ([]Record, error) {
	q := url.Values{"per_page": {"500"}}
	var all []Record
	err := l.paginate(ctx, "/zones/"+url.PathEscape(zoneID)+"/dns_records", q, func() any { return &[]Record{} }, func(v any) {
		all = append(all, *v.(*[]Record)...)
	})
	return all, err
}

func (l *Lister) paginate(ctx context.Context, path string, q url.Values, alloc func() any, collect func(any)) error {
	for page := 1; page <= 100; page++ {
		q.Set("page", strconv.Itoa(page))
		out := alloc()
		info, err := doCall(ctx, l.http, l.base, l.token, http.MethodGet, path+"?"+q.Encode(), nil, out)
		if err != nil {
			return err
		}
		collect(out)
		if info.TotalPages <= page {
			return nil
		}
	}
	return errors.New("cloudflare: too many result pages")
}
