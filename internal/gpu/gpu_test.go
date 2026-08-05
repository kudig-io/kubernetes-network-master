package gpu

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseNCCLLog(t *testing.T) {
	raw := `#       size    count   type  redop   time  algbw  busbw
#       (B)    (elements)            (us)  (GB/s) (GB/s)
        8        2  float    sum   12.5   0.001   0.001
     1024      256  float    sum   25.0   0.05    0.08
  8388608  2097152  float    sum  120.0   2.5     3.0
`
	rep := ParseNCCLLog(raw)
	if len(rep.Lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(rep.Lines))
	}
	// slowest BW should be the 8-byte op (~0.001).
	if rep.SlowestBW.Size != "8" {
		t.Fatalf("slowest BW size = %s, want 8", rep.SlowestBW.Size)
	}
	// slowest latency = highest latency = 120.0us (8M op)
	if rep.SlowestLat.AvgLatency < 100 {
		t.Fatalf("slowest latency = %v, want >100", rep.SlowestLat.AvgLatency)
	}
	// sorted ascending by BW
	if rep.Lines[0].AlgoBW > rep.Lines[len(rep.Lines)-1].AlgoBW {
		t.Fatal("expected lines sorted by BW ascending")
	}
}

func TestParseNCCLLog_Empty(t *testing.T) {
	rep := ParseNCCLLog("")
	if len(rep.Lines) != 0 {
		t.Fatalf("expected 0 lines, got %d", len(rep.Lines))
	}
}

func TestDeriveQoS_Configured(t *testing.T) {
	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "gpu-node-1",
			Annotations: map[string]string{
				"rdma.qos":                    "p1,p2",
				"k8s.v1.cni.cncf.io/networks": "cx5-rdma",
			}},
		Status: corev1.NodeStatus{Capacity: corev1.ResourceList{"nvidia.com/gpu": {}}},
	}
	s := DeriveQoS(node)
	if !s.Configured {
		t.Fatal("expected configured")
	}
	if !strings.Contains(s.Priority, "P1") {
		t.Fatalf("expected P1 priority for rdma annotation, got %s", s.Priority)
	}
}

func TestDeriveQoS_NotConfigured(t *testing.T) {
	node := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n"}}
	s := DeriveQoS(node)
	if s.Configured {
		t.Fatal("expected not configured")
	}
	if !strings.Contains(s.Priority, "P3") {
		t.Fatalf("expected P3 default, got %s", s.Priority)
	}
}
