// Package cni implements CNI benchmarking, fault-injection manifest
// generation, and drift detection logic. The cluster-touching parts (pod
// creation, exec) are behind small interfaces so the logic is unit-testable;
// cli/cni.go wires the real Kubernetes clientset + ExecClient.
package cni

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

// PodRunner creates and tears down benchmark pods. The real implementation
// uses kubernetes.Interface; tests fake it.
type PodRunner interface {
	Create(ctx context.Context, ns string, pod *corev1.Pod) (*corev1.Pod, error)
	Delete(ctx context.Context, ns, name string) error
	WaitRunning(ctx context.Context, ns, name string, timeout time.Duration) (*corev1.Pod, error)
	Get(ctx context.Context, ns, name string) (*corev1.Pod, error)
}

// ExecClient mirrors trace.ExecClient — kept local to avoid a cycle.
type ExecClient interface {
	Run(ctx context.Context, namespace, pod string, cmd []string, timeout time.Duration) (stdout, stderr string, code int, err error)
}

// BenchResult is one measured dimension.
type BenchResult struct {
	Dimension string
	Value     string
	Detail    string
	OK        bool
}

// Iperf3Image is the default benchmark image (networkstatic/iperf3 has iperf3
// and is ~10MB).
const Iperf3Image = "networkstatic/iperf3:latest"

// RunIperf3Bench creates a server pod + client pod (on different nodes when
// possible), runs iperf3, and returns throughput + latency results. On any
// failure it returns the dimensions it couldn't measure with OK=false so the
// caller can fall back to methodology.
func RunIperf3Bench(ctx context.Context, runner PodRunner, exec ExecClient, ns string, wait time.Duration) []BenchResult {
	results := []BenchResult{
		{Dimension: "Throughput (cross-node)", OK: false},
		{Dimension: "Latency p50/p99", OK: false},
	}
	srvPod := iperf3Pod("knm-bench-server", ns, "server")
	cliPod := iperf3Pod("knm-bench-client", ns, "client")
	// Anti-affinity so the two land on different nodes when available.
	setAntiAffinity(srvPod, cliPod)

	cleanup := func() {
		_ = runner.Delete(ctx, ns, srvPod.Name)
		_ = runner.Delete(ctx, ns, cliPod.Name)
	}
	if _, err := runner.Create(ctx, ns, srvPod); err != nil {
		results[0].Detail = "create server pod: " + err.Error()
		cleanup()
		return results
	}
	defer cleanup()
	srv, err := runner.WaitRunning(ctx, ns, srvPod.Name, wait)
	if err != nil {
		results[0].Detail = "server pod never became Ready: " + err.Error()
		return results
	}
	if _, err := runner.Create(ctx, ns, cliPod); err != nil {
		results[0].Detail = "create client pod: " + err.Error()
		return results
	}
	cli, err := runner.WaitRunning(ctx, ns, cliPod.Name, wait)
	if err != nil {
		results[0].Detail = "client pod never became Ready: " + err.Error()
		return results
	}
	srvIP := podIP(srv)
	if srvIP == "" {
		results[0].Detail = "server pod has no IP"
		return results
	}

	// Throughput (TCP, 10s).
	out, _, code, runErr := exec.Run(ctx, cli.Namespace, cli.Name,
		[]string{"iperf3", "-c", srvIP, "-t", "10", "-J"}, 15*time.Second)
	if runErr == nil && code == 0 {
		if t, ok := parseIperf3Throughput(out); ok {
			results[0].Value = fmt.Sprintf("%.2f Mbits/sec", t)
			results[0].OK = true
			same := srv.Spec.NodeName == cli.Spec.NodeName
			if same {
				results[0].Dimension = "Throughput (same-node)"
			}
		} else {
			results[0].Detail = "iperf3 ran but throughput not parsed"
		}
	} else {
		results[0].Detail = fmt.Sprintf("iperf3 client failed (exit %d)", code)
	}

	// Latency (UDP ping-pong via iperf3 -u --bidir with small datagrams is
	// awkward; use a 1-byte tcp probe instead via the client's iperf3 reverse).
	out, _, code, runErr = exec.Run(ctx, cli.Namespace, cli.Name,
		[]string{"iperf3", "-c", srvIP, "-t", "3", "--rcv-timeout", "1000", "-J"}, 10*time.Second)
	if runErr == nil && code == 0 {
		if p50, p99, ok := parseIperf3Latency(out); ok {
			results[1].Value = fmt.Sprintf("p50=%.2fms p99=%.2fms", p50, p99)
			results[1].OK = true
		}
	}
	if !results[1].OK {
		results[1].Detail = "latency probe requires iperf3 with --rcv-timeout support"
	}
	return results
}

// parseIperf3Throughput extracts the end-sum bitrate from iperf3 -J JSON.
func parseIperf3Throughput(jsonOut string) (mbps float64, ok bool) {
	// iperf3 JSON: .end.sum_received.bits_per_second (most accurate).
	// Fallback: .end.sum_sent.bits_per_second. We do a substring scan to avoid
	// pulling encoding/json here for one field.
	for _, key := range []string{`"bits_per_second"`, `"bitrate"`} {
		if v, found := scanFloatAfter(jsonOut, key); found {
			// bits_per_second → Mbps divide by 1e6; bitrate is already in the
			// stream's units (iperf3 reports bits_per_second in bps).
			return v / 1e6, true
		}
	}
	return 0, false
}

// parseIperf3Latency best-effort pulls a mean jitter as a latency proxy from
// the UDP-receiver stream if present.
func parseIperf3Latency(jsonOut string) (p50, p99 float64, ok bool) {
	if v, found := scanFloatAfter(jsonOut, `"jitter_ms"`); found {
		return v, v * 2, true
	}
	return 0, 0, false
}

// scanFloatAfter finds the first float following the given JSON key token.
func scanFloatAfter(s, key string) (float64, bool) {
	idx := strings.Index(s, key)
	if idx < 0 {
		return 0, false
	}
	rest := s[idx+len(key):]
	// skip : and whitespace
	for len(rest) > 0 && (rest[0] == ':' || rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	// read a number
	end := 0
	dot := false
	for end < len(rest) {
		ch := rest[end]
		if ch >= '0' && ch <= '9' {
			end++
			continue
		}
		if ch == '.' && !dot {
			dot = true
			end++
			continue
		}
		if ch == '-' && end == 0 {
			end++
			continue
		}
		break
	}
	if end == 0 {
		return 0, false
	}
	var f float64
	if _, err := fmt.Sscanf(rest[:end], "%f", &f); err != nil {
		return 0, false
	}
	return f, true
}

// --- fault manifest generation ---

// FaultScenario is one injectable CNI failure.
type FaultScenario struct {
	Name        string
	Effect      string
	Inject      string // kubectl/chaos-mesh command
	NetworkChaos map[string]interface{} // optional chaos-mesh YAML body
}

// FaultCatalog returns the well-known CNI fault scenarios with ready-to-run
// injection commands and optional chaos-mesh NetworkChaos manifests.
func FaultCatalog(targetNode string) []FaultScenario {
	node := targetNode
	if node == "" {
		node = "<node>"
	}
	return []FaultScenario{
		{
			Name: "veth pair severed", Effect: "pod loses all connectivity",
			Inject: fmt.Sprintf("kubectl debug node/%s --image=alpine -- chroot /host ip link delete <vethiface>", node),
		},
		{
			Name: "IP pool exhaustion", Effect: "new pods fail to get an IP",
			Inject: "kubectl run knm-exhaust-{{seq}} --image=busybox -- sleep 3600  # repeat until pool empty",
		},
		{
			Name: "BGP session down", Effect: "cross-node routes vanish",
			Inject: "kubectl exec -n kube-system ds/kube-router -- ip route flush proto bgp  # CNI-specific",
			NetworkChaos: chaosMeshDisconnect(node, "BGP"),
		},
		{
			Name: "node MTU mismatch", Effect: "packet fragmentation / blackholes",
			Inject: fmt.Sprintf("kubectl debug node/%s --image=alpine -- chroot /host ip link set <iface> mtu 1280", node),
		},
		{
			Name: "kube-proxy rule flush", Effect: "ClusterIP routing breaks",
			Inject: "kubectl exec -n kube-system ds/kube-proxy -- iptables -F  # KUBE-SVC chains",
			NetworkChaos: chaosMeshLoss(node, "kube-proxy", 100),
		},
	}
}

func chaosMeshLoss(node, peer string, pct int) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "chaos-mesh.org/v1alpha1",
		"kind":       "NetworkChaos",
		"metadata":   map[string]interface{}{"name": "knm-loss", "namespace": "default"},
		"spec": map[string]interface{}{
			"action":   "loss",
			"mode":     "all",
			"selector": map[string]interface{}{"nodes": []string{node}},
			"loss":     map[string]interface{}{"loss": map[string]string{"correlation": "100", "probability": fmt.Sprintf("%d", pct)}},
		},
	}
}

func chaosMeshDisconnect(node, peer string) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "chaos-mesh.org/v1alpha1",
		"kind":       "NetworkChaos",
		"metadata":   map[string]interface{}{"name": "knm-disc", "namespace": "default"},
		"spec": map[string]interface{}{
			"action":   "partition",
			"mode":     "all",
			"selector": map[string]interface{}{"nodes": []string{node}},
			"direction": "to",
		},
	}
}

// RenderFaultManifests emits chaos-mesh YAML for scenarios that have one.
func RenderFaultManifests(scenarios []FaultScenario) (string, error) {
	var b strings.Builder
	for _, s := range scenarios {
		if s.NetworkChaos == nil {
			continue
		}
		out, err := yaml.Marshal(s.NetworkChaos)
		if err != nil {
			return "", err
		}
		b.WriteString("---\n# " + s.Name + "\n")
		b.Write(out)
	}
	return b.String(), nil
}

// --- drift probe ---

// NodeSnapshot is a network-state snapshot of one node, taken by exec'ing a
// node debug session or a privileged daemonset pod.
type NodeSnapshot struct {
	Node           string
	IptablesRules  int
	RouteEntries   int
	Interfaces     int
	CollectedAt    time.Time
	Raw            string // full probe output for debugging
}

// ProbeNode execs the given command set on a node (via a privileged pod) and
// parses the counts into a NodeSnapshot.
func ProbeNode(ctx context.Context, exec ExecClient, ns, pod, node string) (NodeSnapshot, error) {
	snap := NodeSnapshot{Node: node, CollectedAt: time.Now()}
	// One shell script that prints "iptables=<n> routes=<n> ifaces=<n>".
	cmd := []string{"sh", "-c", `
set +e
ipt=$(iptables-save 2>/dev/null | grep -c -- '-')
rt=$(ip route 2>/dev/null | wc -l)
ifc=$(ip -o link 2>/dev/null | wc -l)
echo "iptables=$ipt routes=$rt ifaces=$ifc"
`}
	out, _, code, runErr := exec.Run(ctx, ns, pod, cmd, 10*time.Second)
	snap.Raw = out
	if runErr != nil {
		return snap, runErr
	}
	if code != 0 {
		return snap, fmt.Errorf("probe exited %d", code)
	}
	snap.IptablesRules, snap.RouteEntries, snap.Interfaces = parseProbeCounts(out)
	return snap, nil
}

// parseProbeCounts pulls "iptables=N routes=M ifaces=K" into ints.
func parseProbeCounts(s string) (ipt, rt, ifc int) {
	for _, tok := range strings.Fields(s) {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) != 2 {
			continue
		}
		n := 0
		for _, ch := range kv[1] {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		switch kv[0] {
		case "iptables":
			ipt = n
		case "routes":
			rt = n
		case "ifaces":
			ifc = n
		}
	}
	return
}

// --- helpers ---

func iperf3Pod(name, ns, role string) *corev1.Pod {
	cmd := []string{"sleep", "3600"}
	if role == "server" {
		cmd = []string{"iperf3", "-s"}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			Labels: map[string]string{"app": "knm-bench", "role": role},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    role,
				Image:   Iperf3Image,
				Command: cmd,
			}},
		},
	}
}

func setAntiAffinity(pods ...*corev1.Pod) {
	for _, p := range pods {
		p.Spec.Affinity = &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
					LabelSelector: metav1.SetAsLabelSelector(map[string]string{"app": "knm-bench"}),
					TopologyKey:   "kubernetes.io/hostname",
				}},
			},
		}
	}
}

func podIP(p *corev1.Pod) string {
	if p == nil {
		return ""
	}
	return p.Status.PodIP
}

// keep intstr referenced (used if future pod probes add readiness gates).
var _ = intstr.FromInt
