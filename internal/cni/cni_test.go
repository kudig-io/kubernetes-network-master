package cni

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseIperf3Throughput(t *testing.T) {
	jsonOut := `{"end":{"sum_received":{"bits_per_second":95000000.0}}}`
	mbps, ok := parseIperf3Throughput(jsonOut)
	if !ok {
		t.Fatal("expected to parse throughput")
	}
	if mbps < 94.9 || mbps > 95.1 {
		t.Fatalf("expected ~95 Mbps, got %.2f", mbps)
	}
}

func TestScanFloatAfter(t *testing.T) {
	s := `..."bitrate": 1234.56,...`
	v, ok := scanFloatAfter(s, `"bitrate"`)
	if !ok {
		t.Fatal("expected ok")
	}
	if v < 1234.5 || v > 1234.6 {
		t.Fatalf("expected 1234.56, got %f", v)
	}
}

func TestFaultCatalog_HasInjectionCommands(t *testing.T) {
	scs := FaultCatalog("node-1")
	if len(scs) == 0 {
		t.Fatal("expected scenarios")
	}
	for _, s := range scs {
		if s.Inject == "" {
			t.Fatalf("scenario %q has no inject command", s.Name)
		}
	}
	// At least 2 should have chaos-mesh manifests.
	meshCount := 0
	for _, s := range scs {
		if s.NetworkChaos != nil {
			meshCount++
		}
	}
	if meshCount < 2 {
		t.Fatalf("expected >=2 chaos-mesh manifests, got %d", meshCount)
	}
}

func TestRenderFaultManifests(t *testing.T) {
	scs := FaultCatalog("node-1")
	out, err := RenderFaultManifests(scs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "NetworkChaos") {
		t.Fatalf("expected NetworkChaos in output:\n%s", out)
	}
	if !strings.Contains(out, "chaos-mesh.org/v1alpha1") {
		t.Fatalf("expected apiVersion in output")
	}
}

func TestParseProbeCounts(t *testing.T) {
	ipt, rt, ifc := parseProbeCounts("iptables=142 routes=18 ifaces=7")
	if ipt != 142 || rt != 18 || ifc != 7 {
		t.Fatalf("got ipt=%d rt=%d ifc=%d", ipt, rt, ifc)
	}
}

// fakeExec for drift probe
type fakeExec struct{ out string; code int; err error }
func (f *fakeExec) Run(_ context.Context, _, _ string, _ []string, _ time.Duration) (string, string, int, error) {
	return f.out, "", f.code, f.err
}

func TestProbeNode_ParsesCounts(t *testing.T) {
	fe := &fakeExec{out: "iptables=100 routes=20 ifaces=5\n"}
	snap, err := ProbeNode(context.Background(), fe, "ns", "pod", "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if snap.IptablesRules != 100 || snap.RouteEntries != 20 || snap.Interfaces != 5 {
		t.Fatalf("snap wrong: %+v", snap)
	}
}

func TestProbeNode_ExecError(t *testing.T) {
	fe := &fakeExec{err: errFoo()}
	_, err := ProbeNode(context.Background(), fe, "ns", "pod", "node-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

type errFooType struct{}
func (errFooType) Error() string { return "boom" }
func errFoo() error              { return errFooType{} }
