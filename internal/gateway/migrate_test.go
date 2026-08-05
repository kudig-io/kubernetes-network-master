package gateway

import (
	"testing"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMigrate_BasicIngress(t *testing.T) {
	port := int32(80)
	ing := netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{{
				Host: "app.example.com",
				IngressRuleValue: netv1.IngressRuleValue{
					HTTP: &netv1.HTTPIngressRuleValue{
						Paths: []netv1.HTTPIngressPath{{
							Path:     "/",
							PathType: pathTypePtr(netv1.PathTypePrefix),
							Backend: netv1.IngressBackend{Service: &netv1.IngressServiceBackend{
								Name: "web",
								Port: netv1.ServiceBackendPort{Number: port},
							}},
						}},
					},
				},
			}},
		},
	}
	mig, err := Migrate([]netv1.Ingress{ing}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if mig.Gateway == nil {
		t.Fatal("expected a Gateway")
	}
	if len(mig.HTTPRoutes) != 1 {
		t.Fatalf("expected 1 HTTPRoute, got %d", len(mig.HTTPRoutes))
	}
	rt := mig.HTTPRoutes[0]
	if rt.Namespace != "default" {
		t.Fatalf("route namespace = %q, want default", rt.Namespace)
	}
	if len(rt.Spec.Hostnames) != 1 || string(rt.Spec.Hostnames[0]) != "app.example.com" {
		t.Fatalf("hostnames = %v, want [app.example.com]", rt.Spec.Hostnames)
	}
	if len(rt.Spec.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rt.Spec.Rules))
	}
	if len(rt.Spec.ParentRefs) != 1 || string(rt.Spec.ParentRefs[0].Name) == "" {
		t.Fatalf("expected a parentRef to the gateway")
	}
}

func TestMigrate_TLSAddsHTTPSListener(t *testing.T) {
	ing := netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "default"},
		Spec: netv1.IngressSpec{
			TLS: []netv1.IngressTLS{{Hosts: []string{"secure.example.com"}}},
			Rules: []netv1.IngressRule{{
				Host: "secure.example.com",
				IngressRuleValue: netv1.IngressRuleValue{
					HTTP: &netv1.HTTPIngressRuleValue{Paths: []netv1.HTTPIngressPath{{
						Path: "/", PathType: pathTypePtr(netv1.PathTypePrefix),
						Backend: netv1.IngressBackend{Service: &netv1.IngressServiceBackend{Name: "web"}},
					}}},
				},
			}},
		},
	}
	mig, _ := Migrate([]netv1.Ingress{ing}, Options{})
	if len(mig.Gateway.Spec.Listeners) != 2 {
		t.Fatalf("expected 2 listeners (http+https), got %d", len(mig.Gateway.Spec.Listeners))
	}
	if mig.Gateway.Spec.Listeners[1].TLS == nil {
		t.Fatal("expected TLS config on https listener")
	}
}

func TestMigrate_MultipleHostsMultipleRoutes(t *testing.T) {
	mk := func(host string) netv1.Ingress {
		return netv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: host, Namespace: "default"},
			Spec: netv1.IngressSpec{Rules: []netv1.IngressRule{{
				Host: host,
				IngressRuleValue: netv1.IngressRuleValue{HTTP: &netv1.HTTPIngressRuleValue{Paths: []netv1.HTTPIngressPath{{
					Path: "/", PathType: pathTypePtr(netv1.PathTypePrefix),
					Backend: netv1.IngressBackend{Service: &netv1.IngressServiceBackend{Name: "svc"}},
				}}}},
			}}},
		}
	}
	mig, _ := Migrate([]netv1.Ingress{mk("a.example.com"), mk("b.example.com")}, Options{})
	if len(mig.HTTPRoutes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(mig.HTTPRoutes))
	}
}

func pathTypePtr(t netv1.PathType) *netv1.PathType { return &t }
