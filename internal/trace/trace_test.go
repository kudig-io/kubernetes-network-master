package trace

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeExec is a programmable ExecClient. By default it refuses (noExec-like);
// tests override responses via add().
type fakeExec struct {
	noExec    bool
	byFn      map[string]func(cmd []string) (stdout string, code int)
	defaultFn func(cmd []string) (string, int)
}

func (f *fakeExec) Run(_ context.Context, _, _ string, cmd []string, _ time.Duration) (string, string, int, error) {
	if f.noExec {
		return "", "", 0, errNoExec
	}
	// Match on the first arg (sh -c) substring for routing.
	key := probeKey(cmd)
	if fn, ok := f.byFn[key]; ok {
		out, code := fn(cmd)
		return out, "", code, nil
	}
	if f.defaultFn != nil {
		out, code := f.defaultFn(cmd)
		return out, "", code, nil
	}
	return "", "", 0, fmt.Errorf("no fake response registered for %v", cmd)
}

// probeKey identifies which probe a command is for by inspecting its script.
func probeKey(cmd []string) string {
	joined := strings.Join(cmd, " ")
	switch {
	case strings.Contains(joined, "getent hosts") || strings.Contains(joined, "nslookup"):
		return "dns"
	case strings.Contains(joined, "/dev/tcp") || strings.Contains(joined, "nc -z"):
		return "tcp"
	case strings.Contains(joined, "ipvsadm") || strings.Contains(joined, "iptables-save") || strings.Contains(joined, "nft list"):
		return "rules"
	case strings.Contains(joined, "dfping") || strings.Contains(joined, "-M do"):
		return "mtu"
	}
	return "other"
}

func (f *fakeExec) add(key string, fn func(cmd []string) (string, int)) {
	if f.byFn == nil {
		f.byFn = map[string]func(cmd []string) (string, int){}
	}
	f.byFn[key] = fn
}

// --- fixtures ---

func readyPod(ns, name string, labels map[string]string) *corev1.Pod {
	if labels == nil {
		labels = map[string]string{}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: "node-1", Containers: []corev1.Container{{Name: "main"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.0.0.2",
			ContainerStatuses: []corev1.ContainerStatus{{Name: "main", Ready: true}},
		},
	}
}

func clusterDNSService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.10"},
	}
}

func sampleService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.7.7", Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt(80)}},
		},
	}
}

func endpointSliceFor(svcName string, backendPodName string) *discoveryv1.EndpointSlice {
	ready := true
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName + "-1", Namespace: "default",
			Labels: map[string]string{"kubernetes.io/service-name": svcName},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.2"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "default", Name: backendPodName},
		}},
	}
}

// --- tests ---

func TestRun_APIWalk_HappyPath(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	dst := readyPod("default", "api-pod", map[string]string{"app": "api"})
	cs := fake.NewSimpleClientset(
		src, dst, clusterDNSService(), sampleService(),
		endpointSliceFor("api", "api-pod"),
	)
	// --probe=api: no exec expected.
	res := Run(context.Background(), cs, NoExec, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAPI, Port: 80})
	if res.Broken() {
		t.Fatalf("expected clean path, got broken. hops:\n%s", dump(res.Hops))
	}
	// Must include the new NetworkPolicy hop and the TCP Connect hop (skipped).
	if !hasStage(res.Hops, "NetworkPolicy") {
		t.Fatalf("missing NetworkPolicy hop")
	}
	if !hasStage(res.Hops, "TCP Connect") {
		t.Fatalf("missing TCP Connect hop")
	}
}

func TestRun_EndpointsMissing_FailsAtEndpoints(t *testing.T) {
	src := readyPod("default", "web", nil)
	cs := fake.NewSimpleClientset(src, clusterDNSService(), sampleService())
	// No EndpointSlice for "api".
	res := Run(context.Background(), cs, NoExec, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAPI})
	if !res.Broken() {
		t.Fatalf("expected broken (no endpoints)")
	}
	if firstFail(res.Hops).Stage != "Endpoints" {
		t.Fatalf("expected first FAIL at Endpoints, got %s", firstFail(res.Hops).Stage)
	}
}

func TestRun_NetworkPolicyDenies(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	dst := readyPod("default", "api", map[string]string{"app": "api"})
	deny := netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "default"},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress:     []netv1.NetworkPolicyIngressRule{}, // deny all
		},
	}
	cs := fake.NewSimpleClientset(src, dst, clusterDNSService(), sampleService(), endpointSliceFor("api", "api"), &deny)
	res := Run(context.Background(), cs, NoExec, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAPI})
	np := stageHop(res.Hops, "NetworkPolicy")
	if np == nil {
		t.Fatalf("missing NetworkPolicy hop")
	}
	if np.Status != StatusFail {
		t.Fatalf("expected NetworkPolicy FAIL (deny-all selects api), got %s: %s", np.Status, np.Detail)
	}
}

func TestRun_NetworkPolicyAllowsWhenEmpty(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	dst := readyPod("default", "api", map[string]string{"app": "api"})
	cs := fake.NewSimpleClientset(src, dst, clusterDNSService(), sampleService(), endpointSliceFor("api", "api"))
	res := Run(context.Background(), cs, NoExec, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAPI})
	np := stageHop(res.Hops, "NetworkPolicy")
	if np == nil || np.Status != StatusOK {
		t.Fatalf("expected NetworkPolicy OK (no policies), got %+v", np)
	}
}

func TestRun_ActiveDNSResolve_OK(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	dst := readyPod("default", "api", map[string]string{"app": "api"})
	cs := fake.NewSimpleClientset(src, dst, clusterDNSService(), sampleService(), endpointSliceFor("api", "api"))
	fe := &fakeExec{}
	fe.add("dns", func(_ []string) (string, int) { return "10.96.7.7\n", 0 })
	res := Run(context.Background(), cs, fe, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAuto, Port: 80})
	dns := stageHop(res.Hops, "DNS")
	if dns == nil || dns.Status != StatusOK {
		t.Fatalf("expected DNS OK with active resolve, got %+v", dns)
	}
	if !strings.Contains(dns.Detail, "resolved") {
		t.Fatalf("expected detail to mention resolution, got %q", dns.Detail)
	}
}

func TestRun_ActiveDNSResolve_Fails(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	dst := readyPod("default", "api", map[string]string{"app": "api"})
	cs := fake.NewSimpleClientset(src, dst, clusterDNSService(), sampleService(), endpointSliceFor("api", "api"))
	fe := &fakeExec{}
	fe.add("dns", func(_ []string) (string, int) { return "", 3 }) // exit 3 = no resolver worked
	res := Run(context.Background(), cs, fe, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAuto, Port: 80})
	dns := stageHop(res.Hops, "DNS")
	if dns == nil || dns.Status != StatusFail {
		t.Fatalf("expected DNS FAIL when resolve exits non-zero, got %+v", dns)
	}
}

func TestRun_TCPConnect_OK_Then_Fail(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	dst := readyPod("default", "api", map[string]string{"app": "api"})
	cs := fake.NewSimpleClientset(src, dst, clusterDNSService(), sampleService(), endpointSliceFor("api", "api"))

	// OK case.
	fe := &fakeExec{}
	fe.add("dns", func(_ []string) (string, int) { return "10.96.7.7\n", 0 })
	fe.add("tcp", func(_ []string) (string, int) { return "", 0 })
	res := Run(context.Background(), cs, fe, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAuto, Port: 80})
	tcp := stageHop(res.Hops, "TCP Connect")
	if tcp == nil || tcp.Status != StatusOK {
		t.Fatalf("expected TCP Connect OK, got %+v", tcp)
	}

	// FAIL case: port closed.
	fe2 := &fakeExec{}
	fe2.add("dns", func(_ []string) (string, int) { return "10.96.7.7\n", 0 })
	fe2.add("tcp", func(_ []string) (string, int) { return "connection refused", 1 })
	res2 := Run(context.Background(), cs, fe2, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAuto, Port: 80})
	tcp2 := stageHop(res2.Hops, "TCP Connect")
	if tcp2 == nil || tcp2.Status != StatusFail {
		t.Fatalf("expected TCP Connect FAIL, got %+v", tcp2)
	}
}

func TestRun_NoExec_DegradesDNSAndTCP(t *testing.T) {
	src := readyPod("default", "web", map[string]string{"app": "web"})
	dst := readyPod("default", "api", map[string]string{"app": "api"})
	cs := fake.NewSimpleClientset(src, dst, clusterDNSService(), sampleService(), endpointSliceFor("api", "api"))
	// NoExec client → DNS should still be OK (service present, resolve skipped),
	// TCP Connect should be SKIP.
	res := Run(context.Background(), cs, NoExec, Ref{RefPod, "default", "web"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAuto, Port: 80})
	dns := stageHop(res.Hops, "DNS")
	if dns.Status != StatusOK {
		t.Fatalf("expected DNS OK (skipped resolve) under NoExec, got %+v", dns)
	}
	tcp := stageHop(res.Hops, "TCP Connect")
	if tcp.Status != StatusSkip {
		t.Fatalf("expected TCP Connect SKIP under NoExec, got %+v", tcp)
	}
}

func TestParseResolveOutput(t *testing.T) {
	out := "10.96.7.7\n10.96.7.8\nfoo\n10.0.0.1\n"
	ips := parseResolveOutput(out)
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %v", ips)
	}
}

func TestRun_SourcePodMissing(t *testing.T) {
	cs := fake.NewSimpleClientset(clusterDNSService())
	res := Run(context.Background(), cs, NoExec, Ref{RefPod, "default", "ghost"}, Ref{RefService, "default", "api"}, Options{Probe: ProbeAPI})
	if !res.Broken() {
		t.Fatalf("expected broken (source missing)")
	}
	if firstFail(res.Hops).Stage != "Source Pod" {
		t.Fatalf("expected first FAIL at Source Pod, got %s", firstFail(res.Hops).Stage)
	}
}

// --- helpers ---

func hasStage(hops []Hop, stage string) bool { return stageHop(hops, stage) != nil }

func stageHop(hops []Hop, stage string) *Hop {
	for i := range hops {
		if hops[i].Stage == stage {
			return &hops[i]
		}
	}
	return nil
}

func firstFail(hops []Hop) Hop {
	for _, h := range hops {
		if h.Status == StatusFail {
			return h
		}
	}
	return Hop{}
}

func dump(hops []Hop) string {
	var b strings.Builder
	for _, h := range hops {
		fmt.Fprintf(&b, "  %s [%s]: %s\n", h.Stage, h.Status, h.Detail)
	}
	return b.String()
}

// keep types/util referenced
var _ = types.NamespacedName{}
