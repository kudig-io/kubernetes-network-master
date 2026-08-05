package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kudig-io/knm-cli/internal/depgraph"
	"github.com/kudig-io/knm-cli/internal/output"
)

func newDepgraphCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "depgraph",
		Short: "Generate a Service dependency graph from live cluster resources",
		Long: `Derive a dependency graph from Services, EndpointSlices, and NetworkPolicies
and render it as Mermaid or Graphviz DOT (use -o mermaid or -o dot).

The graph shows: Service → backing Pods (via EndpointSlice readiness), and
NetworkPolicy → Service (when the policy selects pods the service exposes).`,
		Example: `  knm depgraph -o mermaid
  knm depgraph -A -o dot`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cs, err := g.factory.Clientset()
			if err != nil {
				return err
			}
			allNs, _ := cmd.Flags().GetBool("all-namespaces")
			ns, _ := g.factory.Namespace(allNs)

			svcs, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list services: %w", err)
			}
			eps, err := cs.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list endpointslices: %w", err)
			}
			pols, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list networkpolicies: %w", err)
			}
			pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list pods: %w", err)
			}

			graph := depgraph.Build(depgraph.Input{
				Services:        svcs.Items,
				EndpointSlices:  eps.Items,
				NetworkPolicies: pols.Items,
				Pods:            pods.Items,
			})

			// Render: for dot/mermaid, use the Graph; otherwise a node/edge table.
			t := &output.Table{
				Title: "service dependency graph",
				Graph: graph,
			}
			switch g.format() {
			case output.FormatDot, output.FormatMermaid:
				// Graph rendering path; rows unused.
			default:
				t.Headers = []string{"FROM", "EDGE", "TO"}
				for _, e := range graph.Edges {
					t.Rows = append(t.Rows, output.Row{"FROM": {Value: e.From}, "EDGE": {Value: e.Label}, "TO": {Value: e.To}})
				}
				for _, n := range graph.Nodes {
					t.Rows = append(t.Rows, output.Row{"FROM": {Value: n.ID}, "EDGE": {Value: "(" + n.Kind + ")"}, "TO": {Value: n.Label}})
				}
			}
			return g.render(t)
		},
	}
	return cmd
}
