package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kudig-io/knm-cli/internal/cni"
	"github.com/kudig-io/knm-cli/internal/output"
	"github.com/kudig-io/knm-cli/internal/trace"
)

func newCNICmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cni",
		Short: "CNI plugin benchmarking, fault injection, and drift detection",
		Long: `Compare and validate Container Network Interface plugins.

  bench    run an actual iperf3 pod-to-pod throughput/latency benchmark
  fault    list well-known CNI failures with ready-to-run injection commands
  drift    snapshot node network state (iptables/route/iface counts) for diff`,
	}
	cmd.AddCommand(newCNIBenchCmd(g), newCNIFaultCmd(g), newCNIDriftCmd(g))
	return cmd
}

func newCNIBenchCmd(g *GlobalFlags) *cobra.Command {
	var wait time.Duration
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Run an iperf3 pod-to-pod throughput and latency benchmark",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cs, err := g.factory.Clientset()
			if err != nil {
				return err
			}
			ns, _ := g.factory.Namespace(false)
			runner := &k8sPodRunner{cs: cs}
			exec := newCNIExecClient(g.factory)
			cniName := trace.DetectCNI(ctx, cs)

			results := cni.RunIperf3Bench(ctx, runner, exec, ns, wait)
			t := &output.Table{
				Title:   fmt.Sprintf("CNI benchmark (detected: %s)", cniName),
				Headers: []string{"DIMENSION", "RESULT", "STATUS"},
			}
			anyOK := false
			for _, r := range results {
				val := r.Value
				status := "measured"
				if !r.OK {
					status = "degraded"
					if val == "" {
						val = "—"
					}
				} else {
					anyOK = true
				}
				t.Rows = append(t.Rows, output.Row{
					"DIMENSION": {Value: r.Dimension},
					"RESULT":    {Value: val, Wide: r.Detail},
					"STATUS":    {Value: status},
				})
			}
			if !anyOK {
				output.Note(t, "ℹ benchmark pods could not run (RBAC/image pull/pod scheduling); methodology below")
				for _, d := range []string{"Pod-to-Pod latency: iperf3 + netperf", "Cross-node throughput: iperf3 -P10", "NetworkPolicy apply time: time apply → enforce check", "Pod creation readiness: create 100 pods, measure net-ready"} {
					t.Rows = append(t.Rows, output.Row{"DIMENSION": {Value: d}, "RESULT": {Value: "methodology"}, "STATUS": {Value: "guide"}})
				}
			} else {
				output.Note(t, "✓ live iperf3 benchmark completed; pods were cleaned up")
			}
			return g.render(t)
		},
	}
	cmd.Flags().DurationVar(&wait, "wait", 90*time.Second, "max wait for benchmark pods to become Ready")
	return cmd
}

func newCNIFaultCmd(g *GlobalFlags) *cobra.Command {
	var node string
	cmd := &cobra.Command{
		Use:   "fault",
		Short: "List CNI failure scenarios with ready-to-run injection commands",
		RunE: func(cmd *cobra.Command, args []string) error {
			scenarios := cni.FaultCatalog(node)
			// If -o yaml, emit the chaos-mesh manifests.
			if g.format() == output.FormatYAML {
				manifest, err := cni.RenderFaultManifests(scenarios)
				if err != nil {
					return err
				}
				fmt.Fprintln(g.out, manifest)
				return nil
			}
			t := &output.Table{
				Title:   "CNI fault scenarios (copy/paste to inject)",
				Headers: []string{"SCENARIO", "EFFECT", "INJECT"},
			}
			for _, sc := range scenarios {
				t.Rows = append(t.Rows, output.Row{
					"SCENARIO": {Value: sc.Name},
					"EFFECT":   {Value: sc.Effect},
					"INJECT":   {Value: sc.Inject},
				})
			}
			output.Note(t, "use -o yaml to emit chaos-mesh NetworkChaos manifests for the applicable scenarios")
			output.Note(t, "ℹ these are destructive operations — review before running on a real cluster")
			return g.render(t)
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "target node name (templated into injection commands)")
	return cmd
}

func newCNIDriftCmd(g *GlobalFlags) *cobra.Command {
	var sampleNode string
	cmd := &cobra.Command{
		Use:   "drift",
		Short: "Snapshot node network state (iptables/route/interface counts) for drift detection",
		Long: `Exec into a privileged pod on each node (or --node) and snapshot the iptables
rule count, route table size, and interface count. Re-run later to spot drift
(e.g. rule-count growth from a leaky controller).`,
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
			exec := newCNIExecClient(g.factory)
			t := &output.Table{
				Title:   "CNI node network-state snapshot",
				Headers: []string{"NODE", "IPTABLES", "ROUTES", "IFACES", "STATUS"},
			}
			sampled := 0
			for _, n := range nodes.Items {
				if sampleNode != "" && n.Name != sampleNode {
					continue
				}
				ns, pod, ok := findNodeDebugPod(ctx, cs, n.Name)
				if !ok {
					t.Rows = append(t.Rows, output.Row{
						"NODE": {Value: n.Name}, "IPTABLES": {Value: "-"}, "ROUTES": {Value: "-"},
						"IFACES": {Value: "-"}, "STATUS": {Value: "no privileged pod found"},
					})
					continue
				}
				snap, perr := cni.ProbeNode(ctx, exec, ns, pod, n.Name)
				status := "snapshotted"
				if perr != nil {
					status = "probe failed: " + perr.Error()
				}
				t.Rows = append(t.Rows, output.Row{
					"NODE":     {Value: n.Name},
					"IPTABLES": {Value: fmt.Sprintf("%d", snap.IptablesRules)},
					"ROUTES":   {Value: fmt.Sprintf("%d", snap.RouteEntries)},
					"IFACES":   {Value: fmt.Sprintf("%d", snap.Interfaces)},
					"STATUS":   {Value: status, Wide: snap.Raw},
				})
				sampled++
			}
			if sampled == 0 {
				output.Note(t, "no nodes could be probed; run knm cni fault to set up a privileged debug pod")
			}
			output.Note(t, "ℹ re-run after a change to spot drift (rule-count growth, route leaks)")
			return g.render(t)
		},
	}
	cmd.Flags().StringVar(&sampleNode, "node", "", "limit the snapshot to a single node")
	return cmd
}
