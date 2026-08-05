package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kudig-io/knm-cli/internal/kube"
	"github.com/kudig-io/knm-cli/internal/output"
	"github.com/kudig-io/knm-cli/internal/trace"
)

func newMCCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mc",
		Short: "Multi-cluster and hybrid-cloud networking",
		Long: `Operate across multiple clusters via kubeconfig contexts.

  topo          cross-cluster service topology (read all contexts)
  policy-sync   diff a NetworkPolicy across contexts (dry-run)
  connectivity  hybrid-cloud MTU/route/connectivity self-check`,
	}
	cmd.AddCommand(newMCTopoCmd(g), newMCPolicySyncCmd(g), newMCConnectivityCmd(g))
	return cmd
}

func newMCTopoCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "topo",
		Short: "Cross-cluster service topology from all kubeconfig contexts",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := g.factory.Raw.ToRawKubeConfigLoader().RawConfig()
			if err != nil {
				return fmt.Errorf("read kubeconfig: %w", err)
			}
			contexts := make([]string, 0, len(raw.Contexts))
			for k := range raw.Contexts {
				contexts = append(contexts, k)
			}
			sort.Strings(contexts)

			t := &output.Table{
				Title:   "cross-cluster topology",
				Headers: []string{"CONTEXT", "CLUSTER", "NAMESPACE", "COUNT(svc)"},
				Graph:   &output.Graph{Label: "cross-cluster services"},
			}
			for _, ctxName := range contexts {
				cs, err := clientsetForContext(g, ctxName)
				if err != nil {
					t.Rows = append(t.Rows, output.Row{
						"CONTEXT": {Value: ctxName}, "CLUSTER": {Value: "?"}, "NAMESPACE": {Value: "-"}, "COUNT(svc)": {Value: "err"},
					})
					continue
				}
				svcs, err := cs.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
				if err != nil {
					t.Rows = append(t.Rows, output.Row{
						"CONTEXT": {Value: ctxName}, "CLUSTER": {Value: raw.Contexts[ctxName].Cluster},
						"NAMESPACE": {Value: "-"}, "COUNT(svc)": {Value: "err"},
					})
					continue
				}
				byNS := map[string]int{}
				for _, s := range svcs.Items {
					byNS[s.Namespace]++
				}
				for ns, n := range byNS {
					t.Rows = append(t.Rows, output.Row{
						"CONTEXT":    {Value: ctxName},
						"CLUSTER":    {Value: raw.Contexts[ctxName].Cluster},
						"NAMESPACE":  {Value: ns},
						"COUNT(svc)": {Value: fmt.Sprintf("%d", n)},
					})
				}
			}
			output.NYI(t, "cross-cluster call-edge inference (Submariner/ClusterMesh service-import + latency)")
			return g.render(t)
		},
	}
	return cmd
}

func newMCPolicySyncCmd(g *GlobalFlags) *cobra.Command {
	var policyName string
	cmd := &cobra.Command{
		Use:   "policy-sync",
		Short: "Dry-run diff a NetworkPolicy across all contexts",
		RunE: func(cmd *cobra.Command, args []string) error {
			if policyName == "" {
				return fail("provide --name <NetworkPolicy>")
			}
			raw, err := g.factory.Raw.ToRawKubeConfigLoader().RawConfig()
			if err != nil {
				return err
			}
			t := &output.Table{
				Title:   fmt.Sprintf("policy-sync %s", policyName),
				Headers: []string{"CONTEXT", "PRESENT", "DIFF vs CURRENT"},
			}
			current := g.factory.CurrentContext()
			var baseline []byte
			if cs, err := clientsetForContext(g, current); err == nil {
				if p, err := cs.NetworkingV1().NetworkPolicies("").Get(context.Background(), policyName, metav1.GetOptions{}); err == nil {
					baseline, _ = p.Marshal()
				}
			}
			contexts := make([]string, 0, len(raw.Contexts))
			for k := range raw.Contexts {
				contexts = append(contexts, k)
			}
			sort.Strings(contexts)
			for _, ctxName := range contexts {
				cs, err := clientsetForContext(g, ctxName)
				present, diff := "no", "-"
				if err == nil {
					if p, err := cs.NetworkingV1().NetworkPolicies("").Get(context.Background(), policyName, metav1.GetOptions{}); err == nil {
						present = "yes"
						b, _ := p.Marshal()
						if len(baseline) > 0 {
							if string(b) == string(baseline) {
								diff = "identical"
							} else {
								diff = "DIFFERS"
							}
						} else {
							diff = "no-baseline"
						}
					}
				}
				t.Rows = append(t.Rows, output.Row{
					"CONTEXT":         {Value: ctxName},
					"PRESENT":         {Value: present},
					"DIFF vs CURRENT": {Value: diff},
				})
			}
			output.NYI(t, "CNI-aware translation (same policy, different CNI semantics) + apply --dry-run")
			return g.render(t)
		},
	}
	cmd.Flags().StringVar(&policyName, "name", "", "NetworkPolicy name to sync across contexts")
	return cmd
}

func newMCConnectivityCmd(g *GlobalFlags) *cobra.Command {
	var activeConn bool
	cmd := &cobra.Command{
		Use:   "connectivity",
		Short: "Hybrid-cloud MTU / route / connectivity self-check (active probe)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cs, err := g.factory.Clientset()
			if err != nil {
				return err
			}
			nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return err
			}
			t := &output.Table{
				Title:   "hybrid-cloud connectivity",
				Headers: []string{"NODE", "INTERNAL IP", "REGION", "PODCIDR", "MTU", "STATUS"},
			}
			// Find a representative pod to run probes from (any running pod).
			probeNS, probePod, haveProbe := findRepresentativePod(ctx, cs)
			var exec *mcExecClient
			if activeConn && haveProbe {
				exec = &mcExecClient{inner: kube.NewRemoteExecutor(g.factory)}
			}
			for _, n := range nodes.Items {
				ip := nodeInternalIP(n)
				region := n.Labels["topology.kubernetes.io/region"]
				cidr := "<none>"
				if len(n.Spec.PodCIDRs) > 0 {
					cidr = n.Spec.PodCIDRs[0]
				}
				mtu, status := "—", "baseline"
				if activeConn {
					if !haveProbe {
						mtu, status = "—", "no probe pod"
					} else if ip == "" {
						mtu, status = "—", "no node IP"
					} else if exec != nil {
						m, s, ok := probeNodeMTU(ctx, *exec, probeNS, probePod, ip)
						if ok {
							mtu, status = m, s
						} else {
							mtu, status = "—", s
						}
					}
				}
				t.Rows = append(t.Rows, output.Row{
					"NODE":        {Value: n.Name},
					"INTERNAL IP": {Value: ip},
					"REGION":      {Value: region},
					"PODCIDR":     {Value: cidr},
					"MTU":         {Value: mtu},
					"STATUS":      {Value: status},
				})
			}
			if !activeConn {
				output.Note(t, "ℹ baseline only; re-run with --active to df-ping each node's IP from a probe pod")
			} else {
				output.Note(t, "✓ active MTU probe from %s/%s; route-symmetry / VPC-reachability checks are roadmap", probeNS, probePod)
			}
			return g.render(t)
		},
	}
	cmd.Flags().BoolVar(&activeConn, "active", false, "actively df-ping each node IP from a probe pod (needs pods/exec)")
	return cmd
}

// findRepresentativePod returns any Running pod to exec probes from. Prefers
// kube-system, then the default namespace.
func findRepresentativePod(ctx context.Context, cs mcClientset) (ns, pod string, ok bool) {
	for _, cand := range []string{"kube-system", "default"} {
		pods, err := cs.CoreV1().Pods(cand).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, p := range pods.Items {
			if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" {
				return p.Namespace, p.Name, true
			}
		}
	}
	return "", "", false
}

// mcClientset is the subset mc connectivity needs (kept local to avoid
// pulling kubernetes.Interface into the file-wide type).
type mcClientset = kubernetes.Interface

// mcExecClient adapts kube.RemoteExecutor for the MTU probe.
type mcExecClient struct{ inner mcExecer }
type mcExecer interface {
	Run(ctx context.Context, namespace, pod string, cmd []string, timeout time.Duration) (string, string, int, error)
}

func (m mcExecClient) Run(ctx context.Context, ns, pod string, cmd []string, timeout time.Duration) (string, string, int, error) {
	return m.inner.Run(ctx, ns, pod, cmd, timeout)
}

// probeNodeMTU runs the trace MTU probe against a node IP and returns
// (mtuString, statusString, ok).
func probeNodeMTU(ctx context.Context, exec mcExecClient, ns, pod, nodeIP string) (string, string, bool) {
	if exec.inner == nil {
		return "", "no exec", false
	}
	// Reuse the trace package's MTU probe script builder via a local copy.
	cmd := trace.MTUProbeCmd(nodeIP)
	out, _, code, err := exec.Run(ctx, ns, pod, cmd, 12*time.Second)
	if err != nil {
		return "", "exec error", false
	}
	out = strings.TrimSpace(out)
	if code != 0 || out == "" || out == "0" {
		return "", fmt.Sprintf("probe exit %d", code), false
	}
	return out, "probed", true
}

func nodeInternalIP(n corev1.Node) string {
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	return ""
}
