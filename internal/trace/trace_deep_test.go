package trace

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

// kubeProxyPodOnNode builds a kube-proxy DaemonSet pod on a given node.
func kubeProxyPodOnNode(node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-proxy-" + node, Namespace: "kube-system"},
		Spec:       corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "kube-proxy"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// --- rulesHop tests ---

func TestRulesHop_IPVSRulePresent(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	src.Spec.NodeName = "node-1"
	kp := kubeProxyPodOnNode("node-1")
	cs := fake.NewSimpleClientset(src, kp)
	fe := &fakeExec{}
	fe.add("rules", func(_ []string) (string, int) {
		return "ipvs:\nTCP  10.96.7.7:80 rr", 0
	})
	hop := rulesHop(context.Background(), cs, fe, src, "10.96.7.7")
	if hop.Status != StatusOK {
		t.Fatalf("expected OK, got %s: %s (%s)", hop.Status, hop.Detail, hop.Note)
	}
	if !strings.Contains(hop.Detail, "present") {
		t.Fatalf("expected detail to say present, got %q", hop.Detail)
	}
}

func TestRulesHop_RuleMissing(t *testing.T) {
	src := readyPod("default", "web", nil)
	src.Spec.NodeName = "node-1"
	kp := kubeProxyPodOnNode("node-1")
	cs := fake.NewSimpleClientset(src, kp)
	fe := &fakeExec{}
	fe.add("rules", func(_ []string) (string, int) { return "ipvs: no rule for 10.96.7.7", 1 })
	hop := rulesHop(context.Background(), cs, fe, src, "10.96.7.7")
	if hop.Status != StatusFail {
		t.Fatalf("expected FAIL for missing rule, got %s: %s", hop.Status, hop.Detail)
	}
}

func TestRulesHop_NoKubeProxyOnNode(t *testing.T) {
	src := readyPod("default", "web", nil)
	src.Spec.NodeName = "node-2"
	// kube-proxy on node-1, source on node-2 → none on source node.
	cs := fake.NewSimpleClientset(src, kubeProxyPodOnNode("node-1"))
	hop := rulesHop(context.Background(), cs, NoExec, src, "10.96.7.7")
	if hop.Status != StatusWarn {
		t.Fatalf("expected WARN when no kube-proxy on node, got %s", hop.Status)
	}
}

func TestRulesHop_NoExecDegrades(t *testing.T) {
	src := readyPod("default", "web", nil)
	src.Spec.NodeName = "node-1"
	cs := fake.NewSimpleClientset(src, kubeProxyPodOnNode("node-1"))
	hop := rulesHop(context.Background(), cs, NoExec, src, "10.96.7.7")
	if hop.Status != StatusSkip {
		t.Fatalf("expected SKIP under NoExec, got %s", hop.Status)
	}
}

// --- pathMtuHop tests ---

func TestPathMtuHop_OK(t *testing.T) {
	src := readyPod("default", "web", nil)
	fe := &fakeExec{}
	fe.add("mtu", func(_ []string) (string, int) { return "1500", 0 })
	hop := pathMtuHop(context.Background(), fe, src, "10.0.0.2", Options{TCPConnectWait: 2 * time.Second})
	if hop.Status != StatusOK {
		t.Fatalf("expected OK, got %s: %s", hop.Status, hop.Detail)
	}
	if !strings.Contains(hop.Detail, "1500") {
		t.Fatalf("expected MTU 1500 in detail, got %q", hop.Detail)
	}
}

func TestPathMtuHop_Sub1500(t *testing.T) {
	src := readyPod("default", "web", nil)
	fe := &fakeExec{}
	fe.add("mtu", func(_ []string) (string, int) { return "1400", 0 })
	hop := pathMtuHop(context.Background(), fe, src, "10.0.0.2", Options{TCPConnectWait: 2 * time.Second})
	if hop.Status != StatusOK {
		t.Fatalf("expected OK, got %s", hop.Status)
	}
	if !strings.Contains(hop.Note, "below 1500") {
		t.Fatalf("expected below-1500 note, got %q", hop.Note)
	}
}

func TestPathMtuHop_NoPing(t *testing.T) {
	src := readyPod("default", "web", nil)
	fe := &fakeExec{}
	fe.add("mtu", func(_ []string) (string, int) { return "0", 1 })
	hop := pathMtuHop(context.Background(), fe, src, "10.0.0.2", Options{})
	if hop.Status != StatusWarn {
		t.Fatalf("expected WARN when no ping, got %s", hop.Status)
	}
}

func TestPathMtuHop_APIModeSkips(t *testing.T) {
	src := readyPod("default", "web", nil)
	hop := pathMtuHop(context.Background(), NoExec, src, "10.0.0.2", Options{Probe: ProbeAPI})
	if hop.Status != StatusSkip {
		t.Fatalf("expected SKIP in API mode, got %s", hop.Status)
	}
}

// --- debugContainerHop tests ---

type fakeInjector struct {
	injected []string
	fail     error
}

func (f *fakeInjector) Inject(_ context.Context, _, _, _ string) (string, error) {
	if f.fail != nil {
		return "", f.fail
	}
	name := fmt.Sprintf("knm-debug-%d", len(f.injected)+1)
	f.injected = append(f.injected, name)
	return name, nil
}

func TestDebugContainerHop_OK(t *testing.T) {
	src := readyPod("default", "web", nil)
	cs := fake.NewSimpleClientset(src)
	inj := &fakeInjector{}
	hop := debugContainerHop(context.Background(), cs, inj, src)
	if hop.Status != StatusOK {
		t.Fatalf("expected OK, got %s: %s", hop.Status, hop.Detail)
	}
	if len(inj.injected) != 1 {
		t.Fatalf("expected 1 injection, got %d", len(inj.injected))
	}
}

func TestDebugContainerHop_NilInjector(t *testing.T) {
	src := readyPod("default", "web", nil)
	cs := fake.NewSimpleClientset(src)
	hop := debugContainerHop(context.Background(), cs, nil, src)
	if hop.Status != StatusSkip {
		t.Fatalf("expected SKIP with nil injector, got %s", hop.Status)
	}
}

func TestDebugContainerHop_InjectFails(t *testing.T) {
	src := readyPod("default", "web", nil)
	cs := fake.NewSimpleClientset(src)
	inj := &fakeInjector{fail: fmt.Errorf("forbidden")}
	hop := debugContainerHop(context.Background(), cs, inj, src)
	if hop.Status != StatusWarn {
		t.Fatalf("expected WARN on inject failure, got %s", hop.Status)
	}
}

// --- integration: full chain with new hops enabled ---

func TestRun_FullChain_WithRulesAndMTU(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	src.Spec.NodeName = "node-1"
	dst := readyPod("default", "api", map[string]string{"app": "api"})
	dst.Status.PodIP = "10.0.0.5"
	cs := fake.NewSimpleClientset(
		src, dst, clusterDNSService(), sampleService(),
		endpointSliceFor("api", "api"), kubeProxyPodOnNode("node-1"),
	)
	fe := &fakeExec{}
	fe.add("dns", func(_ []string) (string, int) { return "10.96.7.7\n", 0 })
	fe.add("tcp", func(_ []string) (string, int) { return "", 0 })
	fe.add("rules", func(_ []string) (string, int) { return "ipvs:\nTCP 10.96.7.7:80 rr", 0 })
	fe.defaultFn = func(_ []string) (string, int) { return "1500", 0 } // mtu probe

	res := Run(context.Background(), cs, fe,
		Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"},
		Options{Probe: ProbeAuto, Port: 80, InspectRules: true, MTUProbe: true})
	if res.Broken() {
		t.Fatalf("expected clean chain, got broken:\n%s", dump(res.Hops))
	}
	if !hasStage(res.Hops, "kube-proxy rules") {
		t.Fatalf("missing kube-proxy rules hop")
	}
	if !hasStage(res.Hops, "Path-MTU") {
		t.Fatalf("missing Path-MTU hop")
	}
}

// keep intstr referenced (used by fixtures indirectly)
var _ = intstr.FromInt
