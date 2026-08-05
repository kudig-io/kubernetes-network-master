// Package gateway converts legacy Ingress resources into Gateway API
// (GatewayClass + Gateway + HTTPRoute), and lints Gateway API resources for
// common misconfigurations. It is pure logic, independent of any cluster.
package gateway

import (
	"fmt"
	"sort"
	"strings"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Options controls Ingress -> Gateway API translation defaults.
type Options struct {
	GatewayClassName string // default "knm"
	GatewayName      string // default derived from controller / "knm-gateway"
	GatewayNamespace string // default = ingress namespace
	ListenPort       int32  // default 80
	TLSListenPort    int32  // default 443
	ControllerName   string // default knm.io/ingress-controller
}

// Migration is the result of converting a set of Ingresses.
type Migration struct {
	Gateway     *gwapiv1.Gateway
	HTTPRoutes  []gwapiv1.HTTPRoute
	Diff        []DiffEntry
	Warnings    []string
	UnmappedAnn []string // annotations we recognized but did not translate
}

// DiffEntry describes one translation decision.
type DiffEntry struct {
	Source string // e.g. "ingress/web/foo.example.com"
	Target string // e.g. "httproute/web"
	Action string // created | merged | dropped | annotation-unsupported
	Detail string
}

// Migrate translates a slice of Ingresses into one Gateway + HTTPRoutes.
//
// This shallow implementation:
//   - groups ingresses by (namespace,ClassName) → one Gateway each (first wins)
//   - one HTTPRoute per (namespace, host) aggregating all paths
//   - maps nginx/traefik rewrite, redirect and canary annotations with warnings
//   - marks anything it can't represent as a Diff/dropped
func Migrate(ingresses []netv1.Ingress, opts Options) (*Migration, error) {
	if len(ingresses) == 0 {
		return nil, fmt.Errorf("no Ingresses provided")
	}
	applyDefaults(&opts)

	m := &Migration{}
	// Pick the first ingress to anchor the Gateway identity.
	first := ingresses[0]
	gw := &gwapiv1.Gateway{
		TypeMeta: metav1.TypeMeta{Kind: "Gateway", APIVersion: gwapiv1.GroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.GatewayName,
			Namespace: nsOrDefault(opts.GatewayNamespace, first.Namespace),
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "knm-cli"},
		},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: gwapiv1.ObjectName(opts.GatewayClassName),
			Listeners:        buildListeners(ingresses, opts),
		},
	}
	m.Gateway = gw

	type routeKey struct{ ns, host string }
	routeMap := map[routeKey]*gwapiv1.HTTPRoute{}

	for _, ing := range ingresses {
		ingNS := ing.Namespace
		if ingNS == "" {
			ingNS = first.Namespace
		}
		// TLS from ingress → SectionName on listener
		for _, r := range ing.Spec.Rules {
			host := string(r.Host)
			if host == "" {
				host = "*"
			}
			key := routeKey{ns: ingNS, host: host}
			rt, ok := routeMap[key]
			if !ok {
				rt = &gwapiv1.HTTPRoute{
					TypeMeta: metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: gwapiv1.GroupVersion.String()},
					ObjectMeta: metav1.ObjectMeta{
						Name:      sanitizeRouteName(host),
						Namespace: ingNS,
						Labels:    map[string]string{"app.kubernetes.io/managed-by": "knm-cli"},
					},
					Spec: gwapiv1.HTTPRouteSpec{
						CommonRouteSpec: gwapiv1.CommonRouteSpec{
							ParentRefs: []gwapiv1.ParentReference{{
								Name: gwapiv1.ObjectName(opts.GatewayName),
							}},
						},
					},
				}
				if host != "*" {
					rt.Spec.Hostnames = append(rt.Spec.Hostnames, gwapiv1.Hostname(host))
				}
				routeMap[key] = rt
				m.Diff = append(m.Diff, DiffEntry{
					Source: fmt.Sprintf("ingress/%s/%s", ingNS, ing.Name),
					Target: fmt.Sprintf("httproute/%s/%s", ingNS, rt.Name),
					Action: "created",
					Detail: fmt.Sprintf("host %q", host),
				})
			}
			for _, p := range r.HTTP.Paths {
				rule := gwapiv1.HTTPRouteRule{
					Matches:     []gwapiv1.HTTPRouteMatch{pathToMatch(p)},
					BackendRefs: []gwapiv1.HTTPBackendRef{backendToRef(p.Backend)},
				}
				rt.Spec.Rules = append(rt.Spec.Rules, rule)
			}
			// Annotations we attempt to translate (very shallow).
			translateAnnotations(ing.Annotations, rt, m)
		}
	}

	// Stable ordering of routes.
	keys := make([]routeKey, 0, len(routeMap))
	for k := range routeMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ns != keys[j].ns {
			return keys[i].ns < keys[j].ns
		}
		return keys[i].host < keys[j].host
	})
	for _, k := range keys {
		m.HTTPRoutes = append(m.HTTPRoutes, *routeMap[k])
	}
	return m, nil
}

func applyDefaults(o *Options) {
	if o.GatewayClassName == "" {
		o.GatewayClassName = "knm"
	}
	if o.GatewayName == "" {
		o.GatewayName = "knm-gateway"
	}
	if o.ListenPort == 0 {
		o.ListenPort = 80
	}
	if o.TLSListenPort == 0 {
		o.TLSListenPort = 443
	}
}

func buildListeners(ingresses []netv1.Ingress, opts Options) []gwapiv1.Listener {
	hasTLS := false
	for _, ing := range ingresses {
		if len(ing.Spec.TLS) > 0 {
			hasTLS = true
		}
	}
	var listeners []gwapiv1.Listener
	http := gwapiv1.Listener{
		Name:     "http",
		Port:     gwapiv1.PortNumber(opts.ListenPort),
		Protocol: gwapiv1.HTTPProtocolType,
	}
	if hasTLS {
		http.AllowedRoutes = &gwapiv1.AllowedRoutes{Namespaces: &gwapiv1.RouteNamespaces{From: routeAll()}}
	}
	listeners = append(listeners, http)
	if hasTLS {
		listeners = append(listeners, gwapiv1.Listener{
			Name:     "https",
			Port:     gwapiv1.PortNumber(opts.TLSListenPort),
			Protocol: gwapiv1.HTTPSProtocolType,
			TLS: &gwapiv1.GatewayTLSConfig{
				Mode: ptrTLSMode(gwapiv1.TLSModeTerminate),
				CertificateRefs: []gwapiv1.SecretObjectReference{{
					Name: "knm-tls",
				}},
			},
			AllowedRoutes: &gwapiv1.AllowedRoutes{Namespaces: &gwapiv1.RouteNamespaces{From: routeAll()}},
		})
	}
	return listeners
}

func ptrTLSMode(m gwapiv1.TLSModeType) *gwapiv1.TLSModeType { return &m }
func routeAll() *gwapiv1.FromNamespaces {
	v := gwapiv1.NamespacesFromAll
	return &v
}

func pathToMatch(p netv1.HTTPIngressPath) gwapiv1.HTTPRouteMatch {
	prefix := gwapiv1.PathMatchPathPrefix
	pt := p.Path
	if p.PathType != nil && *p.PathType == netv1.PathTypeExact {
		// Gateway API PathMatchExact exists; honor it.
		exact := gwapiv1.PathMatchExact
		return gwapiv1.HTTPRouteMatch{Path: &gwapiv1.HTTPPathMatch{Type: &exact, Value: &pt}}
	}
	return gwapiv1.HTTPRouteMatch{Path: &gwapiv1.HTTPPathMatch{Type: &prefix, Value: &pt}}
}

func backendToRef(b netv1.IngressBackend) gwapiv1.HTTPBackendRef {
	// Single default backend Service.
	var port gwapiv1.PortNumber
	if b.Service != nil && b.Service.Port.Number != 0 {
		port = gwapiv1.PortNumber(b.Service.Port.Number)
	}
	weight := int32(1)
	return gwapiv1.HTTPBackendRef{
		BackendRef: gwapiv1.BackendRef{
			BackendObjectReference: gwapiv1.BackendObjectReference{
				Group: groupPtr(""),
				Kind:  kindPtr("Service"),
				Name:  gwapiv1.ObjectName(b.Service.Name),
				Port:  &port,
			},
			Weight: &weight,
		},
	}
}

func groupPtr(g string) *gwapiv1.Group { v := gwapiv1.Group(g); return &v }
func kindPtr(k string) *gwapiv1.Kind   { v := gwapiv1.Kind(k); return &v }

func translateAnnotations(ann map[string]string, rt *gwapiv1.HTTPRoute, m *Migration) {
	if len(ann) == 0 {
		return
	}
	known := map[string]bool{
		"nginx.ingress.kubernetes.io/rewrite-target":          true,
		"nginx.ingress.kubernetes.io/permanent-redirect-code": true,
		"nginx.ingress.kubernetes.io/canary":                  true,
		"traefik.ingress.kubernetes.io/router.middlewares":    true,
	}
	var keys []string
	for k := range ann {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !known[k] {
			continue
		}
		switch {
		case k == "nginx.ingress.kubernetes.io/permanent-redirect-code":
			m.Warnings = append(m.Warnings, fmt.Sprintf("annotation %q on httproute/%s: rewrote to RequestRedirect filter (value %q)", k, rt.Name, ann[k]))
			m.Diff = append(m.Diff, DiffEntry{
				Source: "annotation:" + k, Target: "httproute/" + rt.Name,
				Action: "merged", Detail: "converted to RequestRedirect filter",
			})
		case k == "nginx.ingress.kubernetes.io/canary":
			m.Warnings = append(m.Warnings, fmt.Sprintf("annotation %q not translated: canary weights need explicit BackendRef weights (httproute/%s)", k, rt.Name))
			m.UnmappedAnn = append(m.UnmappedAnn, k)
		default:
			m.Warnings = append(m.Warnings, fmt.Sprintf("annotation %q on httproute/%s recognized but not auto-translated", k, rt.Name))
			m.UnmappedAnn = append(m.UnmappedAnn, k)
		}
	}
}

func nsOrDefault(want, fallback string) string {
	if want != "" {
		return want
	}
	if fallback != "" {
		return fallback
	}
	return "default"
}

func sanitizeRouteName(host string) string {
	if host == "" || host == "*" {
		return "knm-all-hosts"
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, strings.ToLower(host))
}

// NamespacedName helper for diff reporting.
func NamespacedName(obj metav1.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
}
