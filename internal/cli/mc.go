package cli

import (
	"context"
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kudig-io/knm-cli/internal/output"
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
	cmd := &cobra.Command{
		Use:   "connectivity",
		Short: "Hybrid-cloud MTU / route / connectivity self-check",
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
				Title:   "hybrid-cloud connectivity baseline",
				Headers: []string{"NODE", "INTERNAL IP", "REGION", "PODCIDR", "CHECK"},
			}
			for _, n := range nodes.Items {
				ip := nodeInternalIP(n)
				region := n.Labels["topology.kubernetes.io/region"]
				cidr := "<none>"
				if len(n.Spec.PodCIDRs) > 0 {
					cidr = n.Spec.PodCIDRs[0]
				}
				t.Rows = append(t.Rows, output.Row{
					"NODE":        {Value: n.Name},
					"INTERNAL IP": {Value: ip},
					"REGION":      {Value: region},
					"PODCIDR":     {Value: cidr},
					"CHECK":       {Value: "baseline-collected"},
				})
			}
			output.NYI(t, "active MTU probe (df-ping), route symmetry check, and on-prem↔cloud VPC reachability")
			return g.render(t)
		},
	}
	return cmd
}

func nodeInternalIP(n corev1.Node) string {
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	return ""
}
