package policy

import (
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// DefaultDenyAll constructs a default-deny-all NetworkPolicy for a namespace.
// This is the safe baseline emitted by `knm policy generate` before eBPF-based
// traffic observation refines it into least-privilege rules.
func DefaultDenyAll(namespace, name string) netv1.NetworkPolicy {
	if namespace == "" {
		namespace = "default"
	}
	if name == "" {
		name = "knm-default-deny"
	}
	return netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "knm-cli"},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
			Ingress:     []netv1.NetworkPolicyIngressRule{},
			Egress:      []netv1.NetworkPolicyEgressRule{},
		},
	}
}

// ObservedFlow is one connection seen by the (future) eBPF observer. The
// generator turns these into least-privilege egress rules.
type ObservedFlow struct {
	SrcNamespace string
	SrcPod       string
	DstNamespace string
	DstService   string // preferred; falls back to DstIP
	DstIP        string
	DstPort      int32
	Protocol     corev1.Protocol
}

// LeastPrivilege builds egress NetworkPolicies grouping observed flows per
// source namespace. ipBlock-based rules are emitted when only IPs are known.
func LeastPrivilege(flows []ObservedFlow) []netv1.NetworkPolicy {
	if len(flows) == 0 {
		return nil
	}
	// Group by (ns, podSelector-less) for simplicity in this shallow version.
	byNS := map[string][]ObservedFlow{}
	for _, f := range flows {
		ns := f.SrcNamespace
		if ns == "" {
			ns = "default"
		}
		byNS[ns] = append(byNS[ns], f)
	}
	var out []netv1.NetworkPolicy
	for ns, fl := range byNS {
		rules := []netv1.NetworkPolicyEgressRule{}
		for _, f := range fl {
			port := intstr.FromInt(int(f.DstPort))
			proto := f.Protocol
			if proto == "" {
				proto = corev1.ProtocolTCP
			}
			rule := netv1.NetworkPolicyEgressRule{
				Ports: []netv1.NetworkPolicyPort{{Port: &port, Protocol: &proto}},
			}
			if f.DstIP != "" {
				rule.To = append(rule.To, netv1.NetworkPolicyPeer{IPBlock: &netv1.IPBlock{CIDR: f.DstIP + "/32"}})
			}
			rules = append(rules, rule)
		}
		out = append(out, netv1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "knm-observed-egress",
				Namespace: ns,
				Labels:    map[string]string{"app.kubernetes.io/managed-by": "knm-cli"},
			},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
				Egress:      rules,
			},
		})
	}
	return out
}
