package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseAccessLog parses an nginx/combined/common-log-format access log into
// recorded requests + responses. Each non-empty line becomes one entry.
//
// Supported formats:
//   - nginx combined: `$remote_addr - $remote_user [$time] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
//   - nginx with $request_time: appends the request time in seconds
//
// Lines that don't match are skipped (counted in the returned error count).
func ParseAccessLog(raw string) (reqs []RecordedRequest, resps []RecordedResponse, skipped int, err error) {
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		req, resp, ok := parseCombinedLine(line)
		if !ok {
			skipped++
			continue
		}
		reqs = append(reqs, req)
		resps = append(resps, resp)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, 0, err
	}
	return reqs, resps, skipped, nil
}

// parseCombinedLine parses one combined-format line. Returns ok=false if it
// can't recognize the line.
func parseCombinedLine(line string) (RecordedRequest, RecordedResponse, bool) {
	// Host is unknown from access log; we leave it blank (replay uses Target).
	req := RecordedRequest{}
	resp := RecordedResponse{}

	// Find the quoted request: "...METHOD path HTTP/x.y..."
	r := strings.Index(line, "\"")
	if r < 0 {
		return req, resp, false
	}
	r2 := strings.Index(line[r+1:], "\"")
	if r2 < 0 {
		return req, resp, false
	}
	request := line[r+1 : r+1+r2]
	parts := strings.Fields(request)
	if len(parts) < 2 {
		return req, resp, false
	}
	req.Method = parts[0]
	// The URL recorded is just path+query; replay rewrites the host.
	req.URL = parts[1]
	req.Path = parts[1]

	rest := line[r+1+r2+1:]
	fields := strings.Fields(strings.TrimSpace(rest))
	// fields[0] = status, fields[1] = body_bytes_sent, then optional extras.
	if len(fields) < 2 {
		return req, resp, false
	}
	status, err := strconv.Atoi(fields[0])
	if err != nil {
		return req, resp, false
	}
	bodyBytes, _ := strconv.Atoi(fields[1])
	resp.StatusCode = status
	resp.BodyBytes = bodyBytes

	// Optional trailing request_time (seconds, float) — look for a trailing
	// float token after the standard fields.
	for i := 2; i < len(fields); i++ {
		if f, err := strconv.ParseFloat(fields[i], 64); err == nil {
			resp.Latency = time.Duration(f * float64(time.Second))
			break
		}
	}
	return req, resp, true
}

// ParseHAR parses a HAR (HTTP Archive) JSON document into recorded requests +
// responses. HAR is the browser DevTools / load-tester interchange format and
// carries the richest data (method, url, all headers, body, status, timings).
func ParseHAR(raw []byte) (reqs []RecordedRequest, resps []RecordedResponse, skipped int, err error) {
	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					Method  string `json:"method"`
					URL     string `json:"url"`
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					PostData struct {
						Text string `json:"text"`
					} `json:"postData"`
				} `json:"request"`
				Response struct {
					Status  int `json:"status"`
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					Content struct {
						Size int `json:"size"`
					} `json:"content"`
				} `json:"response"`
				Time int `json:"time"` // ms
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &har); err != nil {
		return nil, nil, 0, fmt.Errorf("parse HAR: %w", err)
	}
	for _, e := range har.Log.Entries {
		req := RecordedRequest{
			Method: e.Request.Method,
			URL:    e.Request.URL,
			Body:   e.Request.PostData.Text,
		}
		req.Headers = map[string]string{}
		for _, h := range e.Request.Headers {
			req.Headers[h.Name] = h.Value
		}
		reqs = append(reqs, req)
		resp := RecordedResponse{
			StatusCode: e.Response.Status,
			BodyBytes:  e.Response.Content.Size,
			Latency:    time.Duration(e.Time) * time.Millisecond,
		}
		resp.Headers = map[string]string{}
		for _, h := range e.Response.Headers {
			resp.Headers[h.Name] = h.Value
		}
		resps = append(resps, resp)
	}
	return reqs, resps, 0, nil
}
