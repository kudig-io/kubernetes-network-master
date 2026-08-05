package gateway

import (
	"fmt"
	"sort"
	"strings"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Severity ranks lint findings.
type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARN"
	SeverityInfo    Severity = "INFO"
)

// Finding is one lint issue.
type Finding struct {
	Severity Severity
	Resource string // kind/ns/name
	Field    string
	Message  string
}

// LintSet holds all Gateway API resources to validate together.
type LintSet struct {
	Gateways        []gwapiv1.Gateway
	HTTPRoutes      []gwapiv1.HTTPRoute
	GatewayClasses  []gwapiv1.GatewayClass
	ReferenceGrants int // count, used in cross-namespace checks messaging
	SecretsByNN     map[string]struct{}
	ServicesByNN    map[string]struct{}
}

// Lint inspects the set and returns findings (stable order).
//
// Checks (shallow, all-CNI-agnostic):
//   - duplicate listener ports/hostname conflicts on the same Gateway
//   - HTTPRoute parentRefs pointing to non-existent Gateways
//   - HTTPRoute backendRefs to unknown Services
//   - TLS listeners with no certificateRefs
//   - cross-namespace backendRefs (warn; needs ReferenceGrant)
//   - empty rules / rules with no matches (info)
func Lint(s LintSet) []Finding {
	var out []Finding
	gwByNN := map[string]*gwapiv1.Gateway{}
	for i := range s.Gateways {
		gw := &s.Gateways[i]
		nn := gw.Namespace + "/" + gw.Name
		gwByNN[nn] = gw
		out = append(out, lintGateway(gw)...)
	}
	for i := range s.HTTPRoutes {
		rt := &s.HTTPRoutes[i]
		out = append(out, lintHTTPRoute(rt, gwByNN, s)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

func severityRank(s Severity) int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

func lintGateway(gw *gwapiv1.Gateway) []Finding {
	var out []Finding
	nn := "gateway/" + gw.Namespace + "/" + gw.Name
	seenPort := map[int32]string{}
	seenHost := map[string]string{}
	for _, l := range gw.Spec.Listeners {
		// TLS without cert ref.
		if l.Protocol == gwapiv1.HTTPSProtocolType || (l.TLS != nil && l.TLS.CertificateRefs == nil) {
			if l.TLS == nil || len(l.TLS.CertificateRefs) == 0 {
				out = append(out, Finding{SeverityError, nn, fmt.Sprintf(".spec.listeners[%s]", l.Name),
					"TLS listener has no certificateRefs — Gateway will not become READY"})
			}
		}
		// Duplicate port.
		if prev, ok := seenPort[int32(l.Port)]; ok && prev != string(l.Name) {
			out = append(out, Finding{SeverityWarning, nn, fmt.Sprintf(".spec.listeners[%s]", l.Name),
				fmt.Sprintf("duplicate port %d with listener %q", l.Port, prev)})
		}
		seenPort[int32(l.Port)] = string(l.Name)

		// Hostname conflict: same hostname bound on the same port by another listener.
		if l.Hostname != nil && *l.Hostname != "" {
			hkey := fmt.Sprintf("%d|%s", l.Port, *l.Hostname)
			if prev, ok := seenHost[hkey]; ok && prev != string(l.Name) {
				out = append(out, Finding{SeverityWarning, nn, fmt.Sprintf(".spec.listeners[%s]", l.Name),
					fmt.Sprintf("hostname %q on port %d also bound by listener %q", *l.Hostname, l.Port, prev)})
			}
			seenHost[hkey] = string(l.Name)
		}
	}
	return out
}

func lintHTTPRoute(rt *gwapiv1.HTTPRoute, gws map[string]*gwapiv1.Gateway, s LintSet) []Finding {
	var out []Finding
	nn := "httproute/" + rt.Namespace + "/" + rt.Name
	// parentRefs existence.
	for _, pr := range rt.Spec.ParentRefs {
		ns := rt.Namespace
		if pr.Namespace != nil && *pr.Namespace != "" {
			ns = string(*pr.Namespace)
		}
		gwKey := ns + "/" + string(pr.Name)
		if _, ok := gws[gwKey]; !ok {
			out = append(out, Finding{SeverityError, nn, ".spec.parentRefs",
				fmt.Sprintf("references gateway %q which is not present in the input set", gwKey)})
		}
	}
	// rules.
	if len(rt.Spec.Rules) == 0 {
		out = append(out, Finding{SeverityWarning, nn, ".spec.rules", "no rules defined"})
	}
	for i, rule := range rt.Spec.Rules {
		if len(rule.Matches) == 0 {
			out = append(out, Finding{SeverityInfo, nn, fmt.Sprintf(".spec.rules[%d].matches", i), "rule has no matches (matches everything)"})
		}
		for j, br := range rule.BackendRefs {
			nnRef := backendRefNN(rt.Namespace, br.BackendObjectReference)
			if br.BackendObjectReference.Group != nil && *br.BackendObjectReference.Group != "" {
				// Non-core backend (e.g. an HTTPRoute to another route). Don't check existence.
				continue
			}
			if s.ServicesByNN != nil {
				if _, ok := s.ServicesByNN[nnRef]; !ok {
					out = append(out, Finding{SeverityError, nn, fmt.Sprintf(".spec.rules[%d].backendRefs[%d]", i, j),
						fmt.Sprintf("references Service %q not found in input set", nnRef)})
				}
			}
			// Cross-namespace.
			if refNS := backendRefNamespace(rt.Namespace, br.BackendObjectReference); refNS != rt.Namespace {
				out = append(out, Finding{SeverityWarning, nn, fmt.Sprintf(".spec.rules[%d].backendRefs[%d]", i, j),
					fmt.Sprintf("cross-namespace backend ref to %q requires a ReferenceGrant in that namespace", nnRef)})
			}
		}
	}
	return out
}

func backendRefNN(routeNS string, br gwapiv1.BackendObjectReference) string {
	ns := backendRefNamespace(routeNS, br)
	return ns + "/" + string(br.Name)
}
func backendRefNamespace(routeNS string, br gwapiv1.BackendObjectReference) string {
	if br.Namespace != nil && *br.Namespace != "" {
		return string(*br.Namespace)
	}
	return routeNS
}

// FindingCell converts a finding to a compact "SEVERITY resource field: msg" string.
func (f Finding) String() string {
	field := f.Field
	if field == "" {
		field = "-"
	}
	return fmt.Sprintf("%s %s %s: %s", f.Severity, f.Resource, strings.TrimSpace(field), f.Message)
}
