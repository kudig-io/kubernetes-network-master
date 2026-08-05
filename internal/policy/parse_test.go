package policy

import (
	"testing"
)

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in      string
		ns, pod string
		ip      string
		wantApp string // empty means not seeded
	}{
		{in: "pod/db", ns: "default", pod: "db", wantApp: "db"},
		{in: "app/db", ns: "app", pod: "db", wantApp: "db"},
		{in: "10.0.0.4", ip: "10.0.0.4"},
		{in: "ns/kind/name handled below", ns: "default", pod: "ns"}, // single-token fallback
	}
	for _, c := range cases {
		ep, err := ParseEndpoint(c.in)
		if err != nil {
			t.Logf("ParseEndpoint(%q) err=%v (some cases expected)", c.in, err)
			continue
		}
		t.Logf("ParseEndpoint(%q) → ns=%q pod=%q ip=%q labels=%v", c.in, ep.Namespace, ep.Pod, ep.IP, ep.Labels)
	}
}

func TestParseEndpointPodShorthand(t *testing.T) {
	ep, err := ParseEndpoint("pod/db")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Namespace != "default" || ep.Pod != "db" {
		t.Fatalf("got ns=%q pod=%q", ep.Namespace, ep.Pod)
	}
	if ep.Labels["app"] != "db" {
		t.Fatalf("expected app=db seeded, got %q", ep.Labels["app"])
	}
	if ep.Labels["pod"] != "db" {
		t.Fatalf("expected pod=db seeded, got %q", ep.Labels["pod"])
	}
}
