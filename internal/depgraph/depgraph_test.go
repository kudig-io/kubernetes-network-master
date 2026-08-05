package depgraph

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kudig-io/knm-cli/internal/output"
)

func TestBuild_ServiceToPodViaEndpointSlice(t *testing.T) {
	svc := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"}}
	eps := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api-1", Namespace: "default",
			Labels: map[string]string{"kubernetes.io/service-name": "api"},
		},
		Endpoints: []discoveryv1.Endpoint{{
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "default", Name: "api-abc"},
			Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(true)},
		}},
	}
	g := Build(Input{Services: []corev1.Service{svc}, EndpointSlices: []discoveryv1.EndpointSlice{eps}})
	if !hasEdge(g, "svc:default/api", "pod:default/api-abc") {
		t.Fatalf("expected edge svc→pod, got edges: %v", edges(g))
	}
	if !hasNode(g, "svc:default/api") || !hasNode(g, "pod:default/api-abc") {
		t.Fatalf("expected service+pod nodes, got: %v", nodes(g))
	}
}

func TestBuild_FallsBackToSelector(t *testing.T) {
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default", Labels: map[string]string{"app": "web"}},
	}
	g := Build(Input{Services: []corev1.Service{svc}, Pods: []corev1.Pod{pod}})
	if !hasEdge(g, "svc:default/web", "pod:default/web-1") {
		t.Fatalf("expected selector edge, got: %v", edges(g))
	}
}

func TestBuild_NetworkPolicyGovernsService(t *testing.T) {
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "api"}},
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "default", Labels: map[string]string{"app": "api"}},
	}
	np := netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "default"},
		Spec:       netv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}},
	}
	g := Build(Input{Services: []corev1.Service{svc}, Pods: []corev1.Pod{pod}, NetworkPolicies: []netv1.NetworkPolicy{np}})
	if !hasEdge(g, "np:default/deny-all", "svc:default/api") {
		t.Fatalf("expected governing edge np→svc, got: %v", edges(g))
	}
}

func TestRenderMermaid_ContainsNodes(t *testing.T) {
	svc := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"}}
	eps := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "default",
			Labels: map[string]string{"kubernetes.io/service-name": "api"}},
		Endpoints: []discoveryv1.Endpoint{{
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "default", Name: "api-x"},
			Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(true)},
		}},
	}
	g := Build(Input{Services: []corev1.Service{svc}, EndpointSlices: []discoveryv1.EndpointSlice{eps}})
	tbl := &output.Table{Graph: g}
	var sb strings.Builder
	if err := output.Render(&sb, tbl, output.FormatMermaid); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, "flowchart") {
		t.Fatalf("mermaid missing flowchart header:\n%s", out)
	}
}

// helpers

func boolPtr(b bool) *bool { return &b }

func hasEdge(g *output.Graph, from, to string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func hasNode(g *output.Graph, id string) bool {
	for _, n := range g.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

func edges(g *output.Graph) []string {
	var out []string
	for _, e := range g.Edges {
		out = append(out, e.From+"->"+e.To)
	}
	return out
}

func nodes(g *output.Graph) []string {
	var out []string
	for _, n := range g.Nodes {
		out = append(out, n.ID)
	}
	return out
}
