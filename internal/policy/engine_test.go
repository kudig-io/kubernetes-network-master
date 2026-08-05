package policy

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// makePolicy is a tiny helper to build a NetworkPolicy in tests.
func makePolicy(name string, sel map[string]string, ingress []netv1.NetworkPolicyIngressRule) netv1.NetworkPolicy {
	return netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: sel},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress:     ingress,
		},
	}
}

func TestSimulate_DefaultAllow(t *testing.T) {
	// No policies: destination is not isolated → default allow.
	eng := NewEngine(nil)
	res := eng.Simulate(Query{
		Dest: Endpoint{Namespace: "default", Labels: labels.Set{"app": "db"}},
		Src:  Endpoint{Namespace: "default", Labels: labels.Set{"app": "app"}},
	})
	if !res.Allowed {
		t.Fatalf("expected default-allow, got denied: %s", res.Reason)
	}
	if res.IngressIsolated {
		t.Fatalf("expected not isolated")
	}
}

func TestSimulate_DenyAll(t *testing.T) {
	pol := makePolicy("deny-all", map[string]string{"app": "db"}, []netv1.NetworkPolicyIngressRule{})
	eng := NewEngine([]netv1.NetworkPolicy{pol})
	res := eng.Simulate(Query{
		Dest: Endpoint{Namespace: "default", Labels: labels.Set{"app": "db"}},
		Src:  Endpoint{Namespace: "default", Labels: labels.Set{"app": "app"}},
	})
	if res.Allowed {
		t.Fatalf("expected denied (deny-all), got allowed")
	}
	if !res.IngressIsolated {
		t.Fatalf("expected ingress-isolated")
	}
}

func TestSimulate_AllowFromLabelPeer(t *testing.T) {
	port := intstr.FromInt(5432)
	proto := corev1.ProtocolTCP
	pol := makePolicy("allow-app", map[string]string{"app": "db"}, []netv1.NetworkPolicyIngressRule{{
		Ports: []netv1.NetworkPolicyPort{{Port: &port, Protocol: &proto}},
		From: []netv1.NetworkPolicyPeer{{
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "app"}},
		}},
	}})
	eng := NewEngine([]netv1.NetworkPolicy{pol})

	// Allowed source.
	res := eng.Simulate(Query{
		Dest:     Endpoint{Namespace: "default", Labels: labels.Set{"app": "db"}},
		Src:      Endpoint{Namespace: "default", Labels: labels.Set{"app": "app"}},
		DestPort: 5432,
	})
	if !res.Allowed {
		t.Fatalf("expected allowed, got denied: %s", res.Reason)
	}

	// Wrong source label → denied.
	res = eng.Simulate(Query{
		Dest:     Endpoint{Namespace: "default", Labels: labels.Set{"app": "db"}},
		Src:      Endpoint{Namespace: "default", Labels: labels.Set{"app": "other"}},
		DestPort: 5432,
	})
	if res.Allowed {
		t.Fatalf("expected denied for wrong source label")
	}

	// Wrong port → denied.
	res = eng.Simulate(Query{
		Dest:     Endpoint{Namespace: "default", Labels: labels.Set{"app": "db"}},
		Src:      Endpoint{Namespace: "default", Labels: labels.Set{"app": "app"}},
		DestPort: 8080,
	})
	if res.Allowed {
		t.Fatalf("expected denied for wrong port")
	}
}

func TestSimulate_IPBlockPeer(t *testing.T) {
	pol := makePolicy("allow-cidr", map[string]string{"app": "db"}, []netv1.NetworkPolicyIngressRule{{
		From: []netv1.NetworkPolicyPeer{{
			IPBlock: &netv1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.0.0.5/32"}},
		}},
	}})
	eng := NewEngine([]netv1.NetworkPolicy{pol})

	res := eng.Simulate(Query{
		Dest: Endpoint{Namespace: "default", Labels: labels.Set{"app": "db"}},
		Src:  Endpoint{IP: "10.0.0.4"},
	})
	if !res.Allowed {
		t.Fatalf("expected allowed for 10.0.0.4, got denied: %s", res.Reason)
	}

	res = eng.Simulate(Query{
		Dest: Endpoint{Namespace: "default", Labels: labels.Set{"app": "db"}},
		Src:  Endpoint{IP: "10.0.0.5"},
	})
	if res.Allowed {
		t.Fatalf("expected denied for excepted IP 10.0.0.5")
	}

	res = eng.Simulate(Query{
		Dest: Endpoint{Namespace: "default", Labels: labels.Set{"app": "db"}},
		Src:  Endpoint{IP: "192.168.1.1"},
	})
	if res.Allowed {
		t.Fatalf("expected denied for IP outside CIDR")
	}
}
