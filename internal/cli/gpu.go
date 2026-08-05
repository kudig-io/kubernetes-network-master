package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kudig-io/knm-cli/internal/ebpf"
	"github.com/kudig-io/knm-cli/internal/output"
)

func newGPUCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gpu",
		Short: "AI/GPU workload networking (RDMA, NCCL analysis, QoS)",
		Long: `Networking tooling for LLM/training clusters on Kubernetes.

  rdma     detect GPU nodes + Multus/SR-IOV RDMA attachments and run a check
  analyze  (eBPF) locate NCCL/AllReduce slow links
  qos      RDMA-vs-HTTP traffic priority status + manager (roadmap)`,
	}
	cmd.AddCommand(newGPURdmaCmd(g), newGPUAnalyzeCmd(g), newGPUQoSCmd(g))
	return cmd
}

func newGPURdmaCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rdma",
		Short: "Detect GPU nodes, Multus/SR-IOV attachments, RDMA readiness",
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
				Title:   "GPU / RDMA node status",
				Headers: []string{"NODE", "GPUs", "MULTUS", "SR-IOV RES", "RDMA IFACES"},
			}
			gpuNodes := 0
			for _, n := range nodes.Items {
				gpus := countGPUs(n)
				if gpus == 0 {
					continue
				}
				gpuNodes++
				t.Rows = append(t.Rows, output.Row{
					"NODE":        {Value: n.Name},
					"GPUs":        {Value: fmt.Sprintf("%d", gpus)},
					"MULTUS":      {Value: hasAnnotation(n, "k8s.v1.cni.cncf.io/networks")},
					"SR-IOV RES":  {Value: listSRIOVResources(n)},
					"RDMA IFACES": {Value: rdmaIfaces(n)},
				})
			}
			if gpuNodes == 0 {
				output.Note(t, "no nodes report nvidia.com/gpu capacity")
			}
			output.NYI(t, "RDMA connectivity verification (rping) and performance baseline")
			return g.render(t)
		},
	}
	return cmd
}

func newGPUAnalyzeCmd(g *GlobalFlags) *cobra.Command {
	var ncclFile string
	cmd := &cobra.Command{
		Use:   "analyze -f nccl-test.log",
		Short: "Parse NCCL-test output to rank slow AllReduce links (eBPF path is roadmap)",
		Long: `Parse an nccl-test log file (-f) and rank operations by bandwidth to surface
the slowest link (the likely AllReduce bottleneck). The eBPF path (live RDMA NIC
stats correlated with NCCL rank) is a roadmap item; this file-based path works
today — pipe in ` + "`nccl-test --verbose`" + ` output.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			st := ebpf.Availability()
			t := &output.Table{
				Title:   "NCCL/AllReduce slowest links",
				Headers: []string{"SIZE", "ALGO BW (GB/s)", "LAT (us)", "VERDICT"},
			}
			if ncclFile != "" {
				raw, err := os.ReadFile(ncclFile)
				if err != nil {
					return fmt.Errorf("read %s: %w", ncclFile, err)
				}
				rep := gpuint.ParseNCCLLog(string(raw))
				if len(rep.Lines) == 0 {
					output.Note(t, "no parseable NCCL-test data lines found in %s", ncclFile)
					return g.render(t)
				}
				// Show the slowest 10 (already sorted ascending by BW).
				shown := 0
				for _, l := range rep.Lines {
					if shown >= 10 {
						break
					}
					verdict := "ok"
					if l.AlgoBW == rep.SlowestBW.AlgoBW {
						verdict = "★ worst throughput"
					} else if l.AvgLatency == rep.SlowestLat.AvgLatency {
						verdict = "★ worst latency"
					}
					t.Rows = append(t.Rows, output.Row{
						"SIZE":          {Value: l.Size},
						"ALGO BW (GB/s)": {Value: fmt.Sprintf("%.3f", l.AlgoBW)},
						"LAT (us)":      {Value: fmt.Sprintf("%.2f", l.AvgLatency)},
						"VERDICT":       {Value: verdict},
					})
					shown++
				}
				output.Note(t, "✓ parsed %d nccl-test lines; worst BW = %.3f GB/s at size %s",
					len(rep.Lines), rep.SlowestBW.AlgoBW, rep.SlowestBW.Size)
			} else {
				if !st.Available {
					output.Note(t, "%s", ebpf.Degrade("gpu analyze"))
				}
				output.Note(t, "ℹ provide -f <nccl-test.log> for file-based analysis; live eBPF RDMA stats is roadmap")
			}
			return g.render(t)
		},
	}
	cmd.Flags().StringVarP(&ncclFile, "filename", "f", "", "nccl-test log file to analyze")
	return cmd
}

func newGPUQoSCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "qos",
		Short: "Per-node RDMA QoS state (from annotations/capacity) + manager (roadmap)",
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
				Title:   "GPU network QoS (derived from node annotations)",
				Headers: []string{"NODE", "CONFIGURED", "PRIORITY", "DETAILS"},
			}
			anyGPU := false
			for _, n := range nodes.Items {
				if countGPUs(n) == 0 {
					continue
				}
				anyGPU = true
				s := gpuint.DeriveQoS(n)
				t.Rows = append(t.Rows, output.Row{
					"NODE":       {Value: n.Name},
					"CONFIGURED": {Value: yesNo(s.Configured)},
					"PRIORITY":   {Value: s.Priority},
					"DETAILS":    {Value: s.Details},
				})
			}
			if !anyGPU {
				output.Note(t, "no nodes report nvidia.com/gpu capacity")
			}
			output.Note(t, "ℹ QoS is derived from Multus/SR-IOV/RoCE annotations; an enforcing DCN/ECN webhook is roadmap")
			return g.render(t)
		},
	}
	return cmd
}

func countGPUs(n corev1.Node) int {
	if n.Status.Capacity == nil {
		return 0
	}
	q := n.Status.Capacity["nvidia.com/gpu"]
	return int(q.Value())
}

func hasAnnotation(n corev1.Node, key string) string {
	if _, ok := n.Annotations[key]; ok {
		return "yes"
	}
	return "no"
}

func listSRIOVResources(n corev1.Node) string {
	out := []string{}
	for k := range n.Status.Capacity {
		ks := string(k)
		if startsWith(ks, "openshift.io/") || startsWith(ks, "intel.com/") || startsWith(ks, "mellanox.com/") {
			out = append(out, ks)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return joinStrings(out, ", ")
}

func rdmaIfaces(n corev1.Node) string {
	if a := n.Annotations["k8s.v1.cni.cncf.io/networks"]; a != "" {
		return a
	}
	return "none-detected"
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
func joinStrings(in []string, sep string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
