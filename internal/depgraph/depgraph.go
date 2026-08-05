// Package depgraph derives a service dependency graph from Kubernetes API
// objects and renders it via the output package (mermaid/dot). Pure logic,
// no cluster access — callers feed it objects read from the API.
package depgraph

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kudig-io/knm-cli/internal/output"
)

// Input bundles the resources to derive dependencies from.
type Input struct {
	Services        []corev1.Service
	EndpointSlices  []discoveryv1.EndpointSlice
	NetworkPolicies []netv1.NetworkPolicy
	Pods            []corev1.Pod // optional, enriches labels
}

// key is the namespace/name identity of a resource, shared by Build and the
// ID-rendering helpers.
type key struct{ ns, name string }

// Build constructs a graph: Services and their backing Pods, plus edges for
// the pods each service selects. This is a shallow but real derivation:
//   - node per Service, node per backing Pod (by endpoint readiness)
//   - edge Service → Pod (selects)
//   - node per NetworkPolicy, edge NetworkPolicy → Service (governs, by selector overlap)
func Build(in Input) *output.Graph {
	g := &output.Graph{Label: "knm dependency graph"}

	addSvc := func(svc corev1.Service) key {
		k := key{ns: svc.Namespace, name: svc.Name}
		g.Nodes = append(g.Nodes, output.GraphNode{
			ID: svcID(k), Label: svc.Name, Kind: "Service",
		})
		return k
	}
	addPod := func(k key, label string) {
		g.Nodes = append(g.Nodes, output.GraphNode{ID: podID(k), Label: label, Kind: "Pod"})
	}

	for _, svc := range in.Services {
		sk := addSvc(svc)
		// EndpointSlice-backed members.
		for _, eps := range in.EndpointSlices {
			if eps.Namespace != svc.Namespace {
				continue
			}
			if owner := svcLabelRef(eps.Labels); owner != "" && owner != svc.Name {
				continue
			}
			for _, ep := range eps.Endpoints {
				if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" {
					continue
				}
				pk := key{ns: ep.TargetRef.Namespace, name: ep.TargetRef.Name}
				addPod(pk, ep.TargetRef.Name)
				g.Edges = append(g.Edges, output.GraphEdge{
					From: svcID(sk), To: podID(pk), Label: portLabel(eps.Ports),
				})
			}
		}
		// Fallback to selector-based matching against pods when no slice.
		if hasEndpoints(g, svcID(sk)) {
			continue
		}
		if svc.Spec.Selector != nil && len(in.Pods) > 0 {
			for _, p := range matchingPods(in.Pods, svc) {
				pk := key{ns: p.Namespace, name: p.Name}
				addPod(pk, p.Name)
				g.Edges = append(g.Edges, output.GraphEdge{
					From: svcID(sk), To: podID(pk), Label: "selector",
				})
			}
		}
	}

	// NetworkPolicy nodes and governing edges.
	for _, np := range in.NetworkPolicies {
		npk := key{ns: np.Namespace, name: np.Name}
		g.Nodes = append(g.Nodes, output.GraphNode{ID: npID(npk), Label: np.Name, Kind: "NetworkPolicy"})
		// Which services in the same namespace have pods the policy selects?
		for _, svc := range in.Services {
			if svc.Namespace != np.Namespace {
				continue
			}
			pods := matchingPods(in.Pods, svc)
			if len(pods) == 0 {
				continue
			}
			if anyPodMatchesPolicy(pods, np) {
				g.Edges = append(g.Edges, output.GraphEdge{
					From: npID(npk), To: svcID(key{svc.Namespace, svc.Name}), Label: "governs",
				})
			}
		}
	}

	dedupe(g)
	return g
}

func svcID(k key) string { return "svc:" + k.ns + "/" + k.name }
func podID(k key) string { return "pod:" + k.ns + "/" + k.name }
func npID(k key) string  { return "np:" + k.ns + "/" + k.name }

func svcLabelRef(l map[string]string) string { return l["kubernetes.io/service-name"] }

func portLabel(ports []discoveryv1.EndpointPort) string {
	var names []string
	for _, p := range ports {
		if p.Name != nil && *p.Name != "" {
			names = append(names, *p.Name)
		} else if p.Port != nil {
			names = append(names, fmt.Sprintf(":%d", *p.Port))
		}
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ",")
}

func hasEndpoints(g *output.Graph, svcNode string) bool {
	for _, e := range g.Edges {
		if e.From == svcNode {
			return true
		}
	}
	return false
}

func matchingPods(pods []corev1.Pod, svc corev1.Service) []corev1.Pod {
	sel := selectorFromMap(svc.Spec.Selector)
	if sel.Empty() {
		return nil
	}
	var out []corev1.Pod
	for _, p := range pods {
		if p.Namespace != svc.Namespace {
			continue
		}
		if sel.Matches(labelsOf(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

func labelsOf(l map[string]string) map[string]string {
	if l == nil {
		return map[string]string{}
	}
	return l
}

// anyPodMatchesPolicy does a shallow check: if the policy's podSelector is
// empty it selects all pods; otherwise we require at least one pod to match
// the selector (best-effort label match).
func anyPodMatchesPolicy(pods []corev1.Pod, np netv1.NetworkPolicy) bool {
	if len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0 {
		return true
	}
	for _, p := range pods {
		if labelsMatchSelector(p.Labels, np.Spec.PodSelector.MatchLabels) {
			return true
		}
	}
	return false
}

func labelsMatchSelector(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// dedupe removes duplicate edges and sorts for stable output.
func dedupe(g *output.Graph) {
	seen := map[string]bool{}
	var edges []output.GraphEdge
	for _, e := range g.Edges {
		k := e.From + "|" + e.To + "|" + e.Label
		if seen[k] {
			continue
		}
		seen[k] = true
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	g.Edges = edges

	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
}

// selectorFromMap builds an intstr-friendly label map matcher. We avoid
// importing labels.Selector to keep this package dependency-light; instead we
// return a thin struct with Empty()/Matches().
type sel struct {
	m map[string]string
}

func selectorFromMap(m map[string]string) sel { return sel{m: m} }

func (s sel) Empty() bool { return len(s.m) == 0 }
func (s sel) Matches(labels map[string]string) bool {
	for k, v := range s.m {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// _ keeps intstr referenced in case future port-resolution lands here.
var _ = intstr.FromInt
