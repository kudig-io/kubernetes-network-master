package observe

import (
	"io"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- DNS metrics parsing ---

type fakeGetter struct{ body string }

func (f fakeGetter) Get(_ string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(f.body)), nil
}

func TestScrapeCoreDNS_OK(t *testing.T) {
	body := `# HELP coredns_dns_requests_total
coredns_dns_requests_total{server="dns://:53",zone="."} 1234
coredns_dns_requests_total{server="dns://:53",zone="example.com."} 50
coredns_dns_responses_total{server="dns://:53",rcode="NOERROR"} 1200
coredns_dns_responses_total{server="dns://:53",rcode="SERVFAIL"} 34
coredns_cache_hits_total{server="dns://:53"} 900
coredns_cache_misses_total{server="dns://:53"} 334
coredns_panic_count_total 2
`
	stats := ScrapeCoreDNS(nil, fakeGetter{body: body}, "http://x:9153/metrics")
	if !stats.Reachable {
		t.Fatal("expected reachable")
	}
	if stats.TotalQueries != 1284 {
		t.Fatalf("total queries = %v, want 1284", stats.TotalQueries)
	}
	if stats.Errors != 34 {
		t.Fatalf("errors = %v, want 34", stats.Errors)
	}
	if stats.Panics != 2 {
		t.Fatalf("panics = %v, want 2", stats.Panics)
	}
	if stats.PerZoneQueries["example.com."] != 50 {
		t.Fatalf("zone queries = %v", stats.PerZoneQueries)
	}
}

func TestScrapeCoreDNS_Unreachable(t *testing.T) {
	stats := ScrapeCoreDNS(nil, failGetter{}, "http://x:9153/metrics")
	if stats.Reachable {
		t.Fatal("expected not reachable")
	}
}

type failGetter struct{}

func (failGetter) Get(_ string) (io.ReadCloser, error) { return nil, io.ErrUnexpectedEOF }

// --- reachability baseline ---

func TestBuildReachabilityBaseline(t *testing.T) {
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default", Labels: map[string]string{"app": "api"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: "default"}},
	}
	ready := true
	slices := []discoveryv1.EndpointSlice{{
		ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "default",
			Labels: map[string]string{"kubernetes.io/service-name": "api"}},
		Endpoints: []discoveryv1.Endpoint{{
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "default", Name: "api"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
	}}
	bl := BuildReachabilityBaseline(pods, slices)
	if len(bl) != 2 {
		t.Fatalf("expected 2 baselines, got %d", len(bl))
	}
	// api pod exposed by default/api
	var apiBl, orphanBl *PodBaseline
	for i := range bl {
		if bl[i].Pod == "api" {
			apiBl = &bl[i]
		}
		if bl[i].Pod == "orphan" {
			orphanBl = &bl[i]
		}
	}
	if apiBl == nil || len(apiBl.ExposedBy) != 1 || apiBl.ExposedBy[0] != "default/api" {
		t.Fatalf("api baseline wrong: %+v", apiBl)
	}
	if orphanBl == nil || len(orphanBl.ExposedBy) != 0 {
		t.Fatalf("orphan should have no exposure, got %+v", orphanBl)
	}
}

// --- events filtering ---

func TestFilterNetworkEvents(t *testing.T) {
	events := []corev1.Event{
		{Reason: "FailedScheduling", Message: "0/3 nodes are available: network not ready", Type: "Warning"},
		{Reason: "Pulled", Message: "image pulled", Type: "Normal"}, // not network
		{Reason: "SomeOther", Message: "connection refused from 1.2.3.4", Type: "Warning"}, // keyword match
	}
	rows := FilterNetworkEvents(events)
	if len(rows) != 2 {
		t.Fatalf("expected 2 network events, got %d", len(rows))
	}
}
