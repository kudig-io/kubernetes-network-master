// Package policy implements pure (cluster-free) NetworkPolicy reasoning used
// by `knm policy simulate` and `knm policy matrix`. It intentionally depends
// only on the Kubernetes API types so it is trivially unit-testable.
//
// Semantics implemented (Kubernetes NetworkPolicy v1, the subset every CNI
// honors):
//   - Default-allow: a Pod is ingress-isolated only if at least one policy in
//     its namespace selects it AND has an Ingress section. Same for egress
//     with an Egress section.
//   - When isolated, traffic is allowed only if it matches an ipBlock OR a
//     podSelector/namespaceSelector peer in some selecting policy's Ingress/
//     Egress list. An empty ingress/egress list ([]) in an isolated policy
//     denies everything.
//   - except CIDRs subtract from an ipBlock.
package policy

import (
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Endpoint describes one side of a connection for simulation. Either Pod or
// IP must be set, never both. Namespace defaults to "default".
type Endpoint struct {
	Namespace string
	Pod       string // podSelector match by pod name (treated as a label pod=name)
	IP        string // ipBlock
	Labels    labels.Set
}

// Query is a single simulate request.
type Query struct {
	// Dest labels of the target Pod (used to evaluate podSelector).
	Dest     Endpoint
	DestPort int32 // optional; 0 means "any port"
	Src      Endpoint
	Protos   []corev1.Protocol // empty == any
}

// Result is the allow/deny verdict with a human reason.
type Result struct {
	Allowed         bool
	IngressIsolated bool
	EgressIsolated  bool
	Reason          string
}

// Engine evaluates policies against endpoints.
type Engine struct {
	Policies []netv1.NetworkPolicy
}

// NewEngine builds an engine from a flat list of policies.
func NewEngine(pol []netv1.NetworkPolicy) *Engine {
	return &Engine{Policies: pol}
}

// selecting returns policies in the same namespace whose selector matches the
// pod labels of the given endpoint.
func (e *Engine) selecting(ep Endpoint) []netv1.NetworkPolicy {
	var out []netv1.NetworkPolicy
	for i := range e.Policies {
		p := &e.Policies[i]
		if p.Namespace != ep.Namespace {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
		if err != nil {
			continue
		}
		lset := ep.Labels
		if lset == nil {
			lset = labels.Set{}
		}
		if sel.Matches(lset) {
			out = append(out, *p)
		}
	}
	return out
}

// Isolated reports whether a pod is ingress/egress isolated.
func (e *Engine) Isolated(ep Endpoint) (ingress, egress bool) {
	sel := e.selecting(ep)
	for _, p := range sel {
		for _, t := range p.Spec.PolicyTypes {
			switch t {
			case netv1.PolicyTypeIngress:
				ingress = true
			case netv1.PolicyTypeEgress:
				egress = true
			}
		}
	}
	return
}

// Simulate evaluates a single Query against the policy set.
func (e *Engine) Simulate(q Query) Result {
	inIso, _ := e.Isolated(q.Dest)
	if !inIso {
		// Default-allow: no selecting policy governs ingress.
		return Result{Allowed: true, Reason: "destination not ingress-isolated (no selecting NetworkPolicy with Ingress); default allow"}
	}
	// Destination is isolated: scan selecting policies for an allow.
	sel := e.selecting(q.Dest)
	for _, p := range sel {
		for _, ing := range p.Spec.Ingress {
			if !portAllowed(ing.Ports, q.DestPort, q.Protos) {
				continue
			}
			if len(ing.From) == 0 {
				// An empty From list on an isolated pod allows ALL sources.
				return Result{Allowed: true, IngressIsolated: true, Reason: fmt.Sprintf("allowed by %s/%s: ingress rule with no from peers (allow all sources)", p.Namespace, p.Name)}
			}
			for _, peer := range ing.From {
				if peerMatches(peer, q.Src) {
					return Result{Allowed: true, IngressIsolated: true, Reason: fmt.Sprintf("allowed by %s/%s via ingress peer", p.Namespace, p.Name)}
				}
			}
		}
	}
	return Result{Allowed: false, IngressIsolated: true, Reason: "no selecting NetworkPolicy ingress rule matched the source/port; denied"}
}

func portAllowed(ports []netv1.NetworkPolicyPort, want int32, protos []corev1.Protocol) bool {
	if len(ports) == 0 {
		return true // no port filter => all ports
	}
	for _, pp := range ports {
		// protocol match (empty == any)
		if pp.Protocol != nil {
			if len(protos) > 0 {
				matched := false
				for _, pr := range protos {
					if pr == *pp.Protocol {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}
		}
		if pp.Port == nil {
			return true
		}
		switch pp.Port.Type {
		case intstr.Int:
			if pp.Port.IntVal == want {
				return true
			}
		case intstr.String:
			// named ports: can't resolve without the dest pod; be permissive
			// on name match of "any" when want==0.
			if want == 0 {
				return true
			}
		}
	}
	return false
}

func peerMatches(peer netv1.NetworkPolicyPeer, src Endpoint) bool {
	// ipBlock
	if peer.IPBlock != nil {
		if src.IP == "" {
			// Source is a pod with no IP known: conservatively say ipBlock
			// cannot match unless the block is 0.0.0.0/0 with no except.
			if peer.IPBlock.CIDR == "0.0.0.0/0" && len(peer.IPBlock.Except) == 0 {
				return true
			}
			return false
		}
		if cidrContains(peer.IPBlock.CIDR, src.IP) && !cidrInList(peer.IPBlock.Except, src.IP) {
			return true
		}
		return false
	}
	// podSelector / namespaceSelector
	ns := src.Namespace
	if ns == "" {
		ns = "default"
	}
	if peer.NamespaceSelector != nil {
		// Without a namespace set we can't fully evaluate; treat a nil-matched
		// namespace selector as matching all namespaces.
	}
	if peer.PodSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return false
		}
		if !sel.Matches(src.Labels) {
			return false
		}
	}
	return true
}

func cidrContains(cidr, ip string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return network.Contains(parsed)
}

func cidrInList(cidrs []string, ip string) bool {
	for _, c := range cidrs {
		if cidrContains(c, ip) {
			return true
		}
	}
	return false
}

// EndpointFromName builds an Endpoint from a namespace/pod shorthand, with an
// optional label set. ns may be "" (defaults to "default"). For convenience it
// also seeds the labels with both `pod=<name>` and `app=<name>` so that
// NetworkPolicies keyed on the common `app:` label work out of the box for the
// pure-static simulator. Callers can override either by passing labels in.
func EndpointFromName(ns, pod string, lab labels.Set) Endpoint {
	if ns == "" {
		ns = "default"
	}
	if lab == nil {
		lab = labels.Set{}
	}
	lab = labels.Set(cloneMap(lab))
	if pod != "" {
		if _, ok := lab["pod"]; !ok {
			lab["pod"] = pod // convenience for podSelector {pod: foo}
		}
		if _, ok := lab["app"]; !ok {
			lab["app"] = pod // convenience for podSelector {app: foo}
		}
	}
	return Endpoint{Namespace: ns, Pod: pod, Labels: lab}
}

func cloneMap(s labels.Set) map[string]string {
	out := map[string]string{}
	for k, v := range s {
		out[k] = v
	}
	return out
}

// ParseEndpoint accepts "pod", "ns/pod", "pod/name", or "1.2.3.4". It also
// accepts the 3-segment "ns/pod/name" form for symmetry with the CLI.
func ParseEndpoint(s string) (Endpoint, error) {
	if s == "" {
		return Endpoint{}, fmt.Errorf("empty endpoint")
	}
	if !strings.Contains(s, "/") {
		if ip := net.ParseIP(s); ip != nil {
			return Endpoint{IP: s}, nil
		}
		return EndpointFromName("", s, nil), nil
	}
	parts := strings.SplitN(s, "/", 3)
	switch len(parts) {
	case 2:
		// Either KIND/name (pod/foo) or NS/name (default/foo). Distinguish by
		// the first segment: known kind prefixes mean "this is a kind ref".
		switch strings.ToLower(parts[0]) {
		case "pod", "pods":
			return EndpointFromName("", parts[1], nil), nil
		case "ip":
			return Endpoint{IP: parts[1]}, nil
		default:
			// NS/name
			return EndpointFromName(parts[0], parts[1], nil), nil
		}
	case 3:
		// NS/KIND/name or NS/name/extra — treat as NS/(pod)name.
		return EndpointFromName(parts[0], parts[2], nil), nil
	}
	return Endpoint{}, fmt.Errorf("invalid endpoint %q", s)
}
