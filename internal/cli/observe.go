package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kudig-io/knm-cli/internal/ebpf"
	"github.com/kudig-io/knm-cli/internal/output"
)

func newObserveCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "observe",
		Short: "eBPF-based real-time network observation (CNI-agnostic)",
		Long: `Real-time Pod-level TCP connection, packet loss, retransmission and latency
observability via eBPF — without binding to a specific CNI like Cilium/Hubble.

Status: eBPF backend not yet wired into this build (see docs/ebpf.md). When the
backend is unavailable, subcommands degrade to an API-level "service map" built
from Services, EndpointSlices and Endpoint objects.`,
	}
	cmd.AddCommand(newObserveFlowsCmd(g), newObserveEventsCmd(g))
	return cmd
}

func newObserveFlowsCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flows",
		Short: "List active Pod-level network flows",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := ebpf.Availability()
			t := &output.Table{
				Title:   "network flows",
				Headers: []string{"SRC POD", "SRC IP", "DST POD/SVC", "DST IP", "PORT", "PROTO", "STATE"},
			}
			if !st.Available {
				output.Note(t, "%s", ebpf.Degrade("observe flows"))
				output.NYI(t, "live eBPF flow capture (libbpf-go backend); rendering API-level service map instead")
				return appendServiceMapRows(context.Background(), g, t)
			}
			output.Note(t, "✓ eBPF backend available — real flow capture hook goes here")
			return g.render(t)
		},
	}
	return cmd
}

func newObserveEventsCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Stream Pod-level network events (loss, retransmit, latency)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := ebpf.Availability()
			t := &output.Table{
				Title:   "network events",
				Headers: []string{"TIME", "POD", "EVENT", "DETAIL"},
			}
			if !st.Available {
				output.Note(t, "%s", ebpf.Degrade("observe events"))
				output.NYI(t, "eBPF tracepoints (tcp_retransmit_skb, kfree_skb, ...); nothing to stream yet")
				return g.render(t)
			}
			return g.render(t)
		},
	}
	return cmd
}

// appendServiceMapRows is the degraded fallback: read Services/Endpoints and
// present them as a static "what could be talking" map.
func appendServiceMapRows(ctx context.Context, g *GlobalFlags, t *output.Table) error {
	cs, err := g.factory.Clientset()
	if err != nil {
		output.Note(t, "could not connect to cluster for fallback service map: %v", err)
		return g.render(t)
	}
	allNs, _ := t2allNs(t)
	ns, _ := g.factory.Namespace(allNs)
	svcs, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		output.Note(t, "list services failed: %v", err)
		return g.render(t)
	}
	for _, s := range svcs.Items {
		for _, p := range s.Spec.Ports {
			t.Rows = append(t.Rows, output.Row{
				"SRC POD":     {Value: "*"},
				"SRC IP":      {Value: s.Spec.ClusterIP},
				"DST POD/SVC": {Value: s.Namespace + "/" + s.Name},
				"DST IP":      {Value: s.Spec.ClusterIP},
				"PORT":        {Value: fmt.Sprintf("%d", p.Port)},
				"PROTO":       {Value: string(p.Protocol)},
				"STATE":       {Value: "service"},
			})
		}
	}
	return g.render(t)
}

// t2allNs is a tiny shim to read the global -A flag without threading a
// *cobra.Command through. It returns false for the fallback (current ns only)
// to keep the degraded output readable.
func t2allNs(_ *output.Table) (bool, error) { return false, nil }
