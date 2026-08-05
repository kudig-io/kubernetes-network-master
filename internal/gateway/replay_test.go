package gateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// --- access-log parser ---

func TestParseAccessLog_Combined(t *testing.T) {
	raw := `10.0.0.1 - - [04/Aug/2026:12:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://app/" "curl/8"
10.0.0.2 - - [04/Aug/2026:12:00:01 +0000] "POST /api/login HTTP/1.1" 401 87 "-" "curl/8" 0.042`
	reqs, resps, skipped, err := ParseAccessLog(raw)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Fatalf("expected 0 skipped, got %d", skipped)
	}
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(reqs))
	}
	if reqs[0].Method != "GET" || reqs[0].Path != "/api/users" {
		t.Fatalf("first req wrong: %+v", reqs[0])
	}
	if resps[0].StatusCode != 200 || resps[0].BodyBytes != 1234 {
		t.Fatalf("first resp wrong: %+v", resps[0])
	}
	// Second line has request_time 0.042 → latency populated.
	if resps[1].Latency == 0 {
		t.Fatalf("expected latency on second resp, got 0")
	}
	if resps[1].StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resps[1].StatusCode)
	}
}

func TestParseAccessLog_SkipsJunk(t *testing.T) {
	raw := "not a log line\n\nalso garbage"
	_, _, skipped, err := ParseAccessLog(raw)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 2 {
		t.Fatalf("expected 2 skipped, got %d", skipped)
	}
}

// --- HAR parser ---

func TestParseHAR(t *testing.T) {
	har := []byte(`{"log":{"entries":[
		{"request":{"method":"GET","url":"https://prod.example.com/api/x","headers":[{"name":"X-Trace","value":"1"}]},"response":{"status":200,"headers":[],"content":{"size":500}},"time":42}
	]}}`)
	reqs, resps, _, err := ParseHAR(har)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("expected 1 req, got %d", len(reqs))
	}
	if reqs[0].Headers["X-Trace"] != "1" {
		t.Fatalf("expected header preserved, got %v", reqs[0].Headers)
	}
	if resps[0].Latency != 42*time.Millisecond {
		t.Fatalf("expected 42ms latency, got %v", resps[0].Latency)
	}
}

// --- replay engine ---

// fakeDoer returns a scripted response per request.
type fakeDoer struct {
	statuses []int
	called   int
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	status := 200
	if f.called < len(f.statuses) {
		status = f.statuses[f.called]
	}
	f.called++
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Length": []string{"100"}},
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func TestReplay_MatchAll(t *testing.T) {
	reqs := []RecordedRequest{
		{Method: "GET", URL: "/a"},
		{Method: "GET", URL: "/b"},
	}
	baselines := []RecordedResponse{
		{StatusCode: 200, Latency: 10 * time.Millisecond},
		{StatusCode: 200, Latency: 10 * time.Millisecond},
	}
	rep := Replay(context.Background(), reqs, baselines, ReplayConfig{
		Target: "http://gateway.staging:8080",
		Doer:   &fakeDoer{statuses: []int{200, 200}},
	})
	if rep.Matched != 2 {
		t.Fatalf("expected 2 matches, got %d (diffs=%d errors=%d)", rep.Matched, rep.StatusDiffs, rep.Errors)
	}
}

func TestReplay_StatusDiff(t *testing.T) {
	reqs := []RecordedRequest{{Method: "GET", URL: "/a"}}
	baselines := []RecordedResponse{{StatusCode: 200}}
	rep := Replay(context.Background(), reqs, baselines, ReplayConfig{
		Target: "http://gw",
		Doer:   &fakeDoer{statuses: []int{502}},
	})
	if rep.StatusDiffs != 1 {
		t.Fatalf("expected 1 status-diff, got %d", rep.StatusDiffs)
	}
	if rep.Results[0].Status != "status-diff" {
		t.Fatalf("expected status-diff, got %s", rep.Results[0].Status)
	}
}

func TestReplay_RewritesURLToTarget(t *testing.T) {
	doer := &captureDoer{}
	reqs := []RecordedRequest{{Method: "GET", URL: "https://prod.example.com/api/x?foo=1"}}
	Replay(context.Background(), reqs, nil, ReplayConfig{Target: "http://gw.staging:8080", Doer: doer})
	if doer.got == nil {
		t.Fatal("no request captured")
	}
	if doer.got.URL.Path != "/api/x" {
		t.Fatalf("expected path /api/x, got %s", doer.got.URL.Path)
	}
	if doer.got.URL.Host != "gw.staging:8080" {
		t.Fatalf("expected host rewritten, got %s", doer.got.URL.Host)
	}
	if doer.got.URL.RawQuery != "foo=1" {
		t.Fatalf("expected query preserved, got %s", doer.got.URL.RawQuery)
	}
}

type captureDoer struct {
	got *http.Request
}

func (c *captureDoer) Do(req *http.Request) (*http.Response, error) {
	c.got = req
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestReplay_NoBaseline2xxMatch(t *testing.T) {
	reqs := []RecordedRequest{{Method: "GET", URL: "/a"}}
	rep := Replay(context.Background(), reqs, nil, ReplayConfig{
		Target: "http://gw",
		Doer:   &fakeDoer{statuses: []int{204}},
	})
	if rep.Matched != 1 {
		t.Fatalf("expected match for 2xx with no baseline, got %d", rep.Matched)
	}
}
