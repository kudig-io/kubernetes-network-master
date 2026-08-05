// Package observe holds non-eBPF observability logic: CoreDNS metrics parsing,
// a reachability baseline derived from EndpointSlice/Service, and Kubernetes
// Events filtering. These power the degrade paths of `knm security` and
// `knm observe`, so those commands produce real signal without libbpf.
package observe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
)

// HTTPGetter fetches a URL body. *http.Client satisfies it; tests fake it.
type HTTPGetter interface {
	Get(url string) (io.ReadCloser, error)
}

// DNSStats are the CoreDNS metrics we surface.
type DNSStats struct {
	Server          string
	TotalQueries    float64
	Errors          float64
	CacheHits       float64
	CacheMisses     float64
	PerZoneQueries  map[string]float64
	Panics          float64
	Reachable       bool
	Note            string
}

// ScrapeCoreDNS fetches and parses CoreDNS Prometheus metrics from the given
// metrics URL (typically http://<pod-ip>:9153/metrics). Returns zeros with
// Reachable=false on any failure so the caller can degrade cleanly.
func ScrapeCoreDNS(ctx context.Context, getter HTTPGetter, metricsURL string) DNSStats {
	stats := DNSStats{Server: metricsURL, PerZoneQueries: map[string]float64{}}
	if getter == nil {
		getter = httpGetter{}
	}
	rc, err := getter.Get(metricsURL)
	if err != nil {
		stats.Note = "scrape failed: " + err.Error()
		return stats
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		stats.Note = "read body failed: " + err.Error()
		return stats
	}
	stats.Reachable = true
	parseCoreDNSMetrics(string(body), &stats)
	return stats
}

// parseCoreDNSMetrics extracts the metrics we care about from a Prometheus
// text exposition body. It scans line-by-line for known CoreDNS metric names.
func parseCoreDNSMetrics(body string, stats *DNSStats) {
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, labels, value := splitPromLine(line)
		switch name {
		case "coredns_dns_requests_total":
			stats.TotalQueries += value
			if zone := labels["zone"]; zone != "" {
				stats.PerZoneQueries[zone] += value
			}
		case "coredns_dns_responses_total":
			if rcode := labels["rcode"]; rcode != "" && rcode != "NOERROR" {
				stats.Errors += value
			}
		case "coredns_cache_hits_total":
			stats.CacheHits += value
		case "coredns_cache_misses_total":
			stats.CacheMisses += value
		case "coredns_panic_count_total":
			stats.Panics += value
		}
	}
}

// splitPromLine parses "metric_name{label="val"} 123.4" into name, labels, value.
func splitPromLine(line string) (name string, labels map[string]string, value float64) {
	labels = map[string]string{}
	braceStart := strings.Index(line, "{")
	spaceIdx := strings.Index(line, " ")
	if braceStart < 0 {
		// no labels: "name value"
		if spaceIdx < 0 {
			return line, labels, 0
		}
		name = line[:spaceIdx]
		value = parsePromFloat(line[spaceIdx+1:])
		return name, labels, value
	}
	name = line[:braceStart]
	braceEnd := strings.Index(line, "}")
	if braceEnd < 0 {
		return name, labels, 0
	}
	labels = parsePromLabels(line[braceStart+1 : braceEnd])
	rest := strings.TrimSpace(line[braceEnd+1:])
	value = parsePromFloat(rest)
	return name, labels, value
}

func parsePromLabels(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		v := strings.Trim(kv[1], `"`)
		out[strings.TrimSpace(kv[0])] = v
	}
	return out
}

func parsePromFloat(s string) float64 {
	s = strings.TrimSpace(s)
	var f float64
	if _, err := fmt.Sscanf(s, "%f", &f); err != nil {
		return 0
	}
	return f
}

type httpGetter struct{}

func (httpGetter) Get(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// --- reachability baseline (non-eBPF security baseline) ---

// PodBaseline is the reachability baseline for one Pod: which Services expose
// it (and thus which clients *could* reach it). This is the non-eBPF fallback
// for `knm security baseline`.
type PodBaseline struct {
	Pod       string
	Namespace string
	ExposedBy []string // service ns/name that select this pod
	Labels    string
}

// BuildReachabilityBaseline computes, for each pod, the services that expose it
// (via EndpointSlice membership). Pods not exposed by any service are flagged —
// they're the "no legitimate inbound" pods that a deviation alert would care
// about first.
func BuildReachabilityBaseline(pods []corev1.Pod, slices []discoveryv1.EndpointSlice) []PodBaseline {
	// Map pod (ns/name) → services that reference it.
	podToSvcs := map[string]map[string]bool{}
	for _, eps := range slices {
		svc := eps.Labels["kubernetes.io/service-name"]
		if svc == "" {
			continue
		}
		svcRef := eps.Namespace + "/" + svc
		for _, ep := range eps.Endpoints {
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" {
				continue
			}
			key := ep.TargetRef.Namespace + "/" + ep.TargetRef.Name
			if podToSvcs[key] == nil {
				podToSvcs[key] = map[string]bool{}
			}
			podToSvcs[key][svcRef] = true
		}
	}
	var out []PodBaseline
	for _, p := range pods {
		key := p.Namespace + "/" + p.Name
		b := PodBaseline{Pod: p.Name, Namespace: p.Namespace, Labels: labelString(p.Labels)}
		for svc := range podToSvcs[key] {
			b.ExposedBy = append(b.ExposedBy, svc)
		}
		sort.Strings(b.ExposedBy)
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Pod < out[j].Pod
	})
	return out
}

func labelString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

// --- Kubernetes Events filtering (observe events degrade path) ---

// EventRow is one filtered network-related Kubernetes Event.
type EventRow struct {
	LastSeen string
	Type     string
	Reason   string
	Object   string
	Message  string
}

// networkEventReasons are the Event reasons most relevant to networking.
var networkEventReasons = map[string]bool{
	"FailedScheduling":  true,
	"Unhealthy":         true,
	"FailedMount":       true,
	"TrafficPolicy":     true,
	"BackOff":           true,
	"NodeNotReady":      true,
	"ContainerNetworkUnavailable": true,
	"NetworkUnavailable": true,
	"DNSRead":           true,
	"DNSWrite":          true,
}

// FilterNetworkEvents picks network-relevant events from a CoreV1 EventList.
func FilterNetworkEvents(events []corev1.Event) []EventRow {
	var out []EventRow
	for _, e := range events {
		if !networkEventReasons[e.Reason] {
			// also keep any event whose message mentions network keywords
			if !mentionsNetwork(e.Message) {
				continue
			}
		}
		row := EventRow{
			Type:   e.Type,
			Reason: e.Reason,
			Object: e.InvolvedObject.Kind + "/" + e.InvolvedObject.Namespace + "/" + e.InvolvedObject.Name,
			Message: strings.TrimSpace(e.Message),
		}
		if !e.LastTimestamp.IsZero() {
			row.LastSeen = e.LastTimestamp.Format(time.RFC3339)
		}
		out = append(out, row)
	}
	return out
}

func mentionsNetwork(msg string) bool {
	low := strings.ToLower(msg)
	for _, kw := range []string{"network", "cni", "iptables", "ipvs", "dns", "route", "subnet", "endpoint", "timeout", "connection refused"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}
