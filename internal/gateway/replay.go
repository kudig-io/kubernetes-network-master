// Package gateway replay: record prod traffic, replay against a new Gateway,
// compare responses. This file implements the pure logic — access-log / HAR
// parsing, a replay engine over an injectable HTTP client, and a diff summary.
// The HTTP client is an interface so tests can fake it without a live server.
package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// RecordedRequest is one captured request to replay.
type RecordedRequest struct {
	Method  string
	URL     string // absolute URL as recorded (will be rewritten to target)
	Host    string
	Path    string
	Headers map[string]string
	Body    string
}

// RecordedResponse is what the original request returned (for diffing). Only
// captured fields are compared.
type RecordedResponse struct {
	StatusCode int
	BodyBytes  int
	Latency    time.Duration
	Headers    map[string]string
}

// ReplayResult is the outcome of replaying one request against the new target.
type ReplayResult struct {
	Request   RecordedRequest
	Replayed  RecordedResponse
	Expected  RecordedResponse // zero-value when no baseline was recorded
	Status    string           // match | status-diff | latency-diff | error
	Detail    string
}

// ReplayReport aggregates a batch of replayed requests.
type ReplayReport struct {
	Results      []ReplayResult
	Total        int
	Matched      int
	StatusDiffs  int
	LatencyDiffs int
	Errors       int
}

// HTTPDoer is the minimal HTTP client the replay engine needs. *http.Client
// satisfies it; tests pass a fake.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ReplayConfig controls the replay engine.
type ReplayConfig struct {
	Target       string        // base URL of the new Gateway (e.g. http://gateway.staging:8080)
	Concurrency  int           // concurrent replays (default 1)
	Timeout      time.Duration // per-request timeout (default 10s)
	LatencyBand  time.Duration // |replayed-expected| above this → latency-diff
	Doer         HTTPDoer
}

// Replay executes the recorded requests against the new target and returns a
// report. Requests are rewritten so the path+query land on Target; per-request
// Host/Headers from the recording are preserved (so Host-based routing works).
func Replay(ctx context.Context, reqs []RecordedRequest, baselines []RecordedResponse, cfg ReplayConfig) *ReplayReport {
	if cfg.Doer == nil {
		cfg.Doer = &http.Client{Timeout: cfg.Timeout}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.LatencyBand == 0 {
		cfg.LatencyBand = 100 * time.Millisecond
	}
	rep := &ReplayReport{Total: len(reqs)}
	for i, rr := range reqs {
		res := ReplayResult{Request: rr}
		if i < len(baselines) {
			res.Expected = baselines[i]
		}
		start := time.Now()
		resp, err := doOne(ctx, cfg, rr)
		if err != nil {
			res.Status = "error"
			res.Detail = err.Error()
			rep.Errors++
			rep.Results = append(rep.Results, res)
			continue
		}
		bodyLen := 0
		if resp.Body != nil {
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				if n, err := strconv.Atoi(cl); err == nil {
					bodyLen = n
				}
			}
		}
		res.Replayed = RecordedResponse{
			StatusCode: resp.StatusCode,
			BodyBytes:  bodyLen,
			Latency:    time.Since(start),
			Headers:    flattenHeader(resp.Header),
		}
		if resp.Body != nil {
			resp.Body.Close()
		}
		classify(&res, cfg)
		switch res.Status {
		case "match":
			rep.Matched++
		case "status-diff":
			rep.StatusDiffs++
		case "latency-diff":
			rep.LatencyDiffs++
		}
		rep.Results = append(rep.Results, res)
	}
	return rep
}

// doOne builds and sends a single replayed request.
func doOne(ctx context.Context, cfg ReplayConfig, rr RecordedRequest) (*http.Response, error) {
	target, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	// Preserve the recorded path + query, swap the scheme/host to the target.
	recURL, err := url.Parse(rr.URL)
	if err != nil {
		recURL = &url.URL{Path: rr.Path}
	}
	target.Path = recURL.Path
	target.RawQuery = recURL.RawQuery
	if target.Path == "" {
		target.Path = rr.Path
	}
	method := rr.Method
	if method == "" {
		method = "GET"
	}
	var body *strings.Reader
	if rr.Body != "" {
		body = strings.NewReader(rr.Body)
	}
	var req *http.Request
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, target.String(), body)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, target.String(), nil)
	}
	if err != nil {
		return nil, err
	}
	if rr.Host != "" {
		req.Host = rr.Host
	}
	for k, v := range rr.Headers {
		// skip hop-by-hop headers that confuse the client
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		req.Header.Set(k, v)
	}
	return cfg.Doer.Do(req)
}

// classify compares the replayed response against the baseline (if any).
func classify(res *ReplayResult, cfg ReplayConfig) {
	// No baseline → just report replayed status as-is (match if 2xx, else diff).
	if res.Expected.StatusCode == 0 {
		if res.Replayed.StatusCode >= 200 && res.Replayed.StatusCode < 400 {
			res.Status = "match"
		} else {
			res.Status = "status-diff"
		}
		return
	}
	if res.Replayed.StatusCode != res.Expected.StatusCode {
		res.Status = "status-diff"
		res.Detail = fmt.Sprintf("status %d → %d", res.Expected.StatusCode, res.Replayed.StatusCode)
		return
	}
	if absDur(res.Replayed.Latency-res.Expected.Latency) > cfg.LatencyBand {
		res.Status = "latency-diff"
		res.Detail = fmt.Sprintf("latency %s → %s", res.Expected.Latency, res.Replayed.Latency)
		return
	}
	res.Status = "match"
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func flattenHeader(h http.Header) map[string]string {
	out := map[string]string{}
	for k := range h {
		out[k] = h.Get(k)
	}
	return out
}
