package gateway

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestLint_TLSWithoutCertRef(t *testing.T) {
	https := gwapiv1.HTTPSProtocolType
	gw := gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "default"},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "knm",
			Listeners:        []gwapiv1.Listener{{Name: "https", Port: 443, Protocol: https}},
		},
	}
	findings := Lint(LintSet{Gateways: []gwapiv1.Gateway{gw}})
	if !hasSeverity(findings, SeverityError) {
		t.Fatalf("expected an ERROR for TLS listener without certRef, got %v", findings)
	}
}

func TestLint_DanglingParentRef(t *testing.T) {
	gw := gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "default"},
		Spec:       gwapiv1.GatewaySpec{GatewayClassName: "knm"},
	}
	rt := gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "default"},
		Spec: gwapiv1.HTTPRouteSpec{
			CommonRouteSpec: gwapiv1.CommonRouteSpec{ParentRefs: []gwapiv1.ParentReference{{Name: "missing"}}},
		},
	}
	findings := Lint(LintSet{Gateways: []gwapiv1.Gateway{gw}, HTTPRoutes: []gwapiv1.HTTPRoute{rt}})
	if !hasMessage(findings, "not present in the input set") {
		t.Fatalf("expected dangling-parent-ref finding, got %v", findings)
	}
}

func TestLint_CrossNamespaceBackendWarns(t *testing.T) {
	port := gwapiv1.PortNumber(80)
	otherNS := gwapiv1.Namespace("other")
	rt := gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "default"},
		Spec: gwapiv1.HTTPRouteSpec{
			Rules: []gwapiv1.HTTPRouteRule{{
				BackendRefs: []gwapiv1.HTTPBackendRef{{BackendRef: gwapiv1.BackendRef{
					BackendObjectReference: gwapiv1.BackendObjectReference{
						Name: "svc", Namespace: &otherNS, Port: &port,
					},
				}}},
			}},
		},
	}
	findings := Lint(LintSet{HTTPRoutes: []gwapiv1.HTTPRoute{rt}})
	if !hasMessage(findings, "cross-namespace backend ref") {
		t.Fatalf("expected cross-namespace warning, got %v", findings)
	}
}

func TestLint_DuplicatePort(t *testing.T) {
	http := gwapiv1.HTTPProtocolType
	gw := gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "default"},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "knm",
			Listeners: []gwapiv1.Listener{
				{Name: "a", Port: 80, Protocol: http},
				{Name: "b", Port: 80, Protocol: http},
			},
		},
	}
	findings := Lint(LintSet{Gateways: []gwapiv1.Gateway{gw}})
	if !hasMessage(findings, "duplicate port") {
		t.Fatalf("expected duplicate-port warning, got %v", findings)
	}
}

func hasSeverity(fs []Finding, s Severity) bool {
	for _, f := range fs {
		if f.Severity == s {
			return true
		}
	}
	return false
}

func hasMessage(fs []Finding, substr string) bool {
	for _, f := range fs {
		if contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
