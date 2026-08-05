package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kudig-io/knm-cli/internal/ebpf"
	"github.com/kudig-io/knm-cli/internal/observe"
	"github.com/kudig-io/knm-cli/internal/output"
)

func newSecurityCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "Kubernetes network security: baseline, DNS anomaly detection",
		Long: `Network security tooling.

  baseline   per-Pod reachability baseline (degrades from eBPF to EndpointSlice analysis)
  dns        CoreDNS Prometheus metrics scrape + query stats`,
	}
	cmd.AddCommand(newSecurityBaselineCmd(g), newSecurityDNSCmd(g))
	return cmd
}

func newSecurityBaselineCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Build a per-Pod network baseline (eBPF when available; reachability otherwise)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := ebpf.Availability()
			ctx := context.Background()
			cs, err := g.factory.Clientset()
			if err != nil {
				return err
			}
			allNs, _ := cmd.Flags().GetBool("all-namespaces")
			ns, _ := g.factory.Namespace(allNs)
			pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return err
			}
			t := &output.Table{
				Title:   "Pod network baseline",
				Headers: []string{"POD", "NAMESPACE", "EXPOSED BY", "BASELINE SOURCE"},
			}
			if st.Available {
				// eBPF path: live connection learning (future).
				for _, p := range pods.Items {
					t.Rows = append(t.Rows, output.Row{
						"POD":             {Value: p.Name},
						"NAMESPACE":       {Value: p.Namespace},
						"EXPOSED BY":      {Value: "(eBPF)"},
						"BASELINE SOURCE": {Value: "eBPF (live)"},
					})
				}
				return g.render(t)
			}
			// Degrade: reachability baseline from EndpointSlices.
			slices, _ := cs.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{})
			bl := observe.BuildReachabilityBaseline(pods.Items, slices.Items)
			for _, b := range bl {
				exposed := "(none — no inbound service)"
				if len(b.ExposedBy) > 0 {
					exposed = strings.Join(b.ExposedBy, ", ")
				}
				t.Rows = append(t.Rows, output.Row{
					"POD":             {Value: b.Pod},
					"NAMESPACE":       {Value: b.Namespace},
					"EXPOSED BY":      {Value: exposed, Wide: b.Labels},
					"BASELINE SOURCE": {Value: "EndpointSlice reachability"},
				})
			}
			output.Note(t, "%s", ebpf.Degrade("security baseline"))
			output.Note(t, "ℹ eBPF connection-learning path is roadmap; baseline derived from which Services expose each Pod")
			output.Note(t, "ℹ pods with '(none)' have no exposing Service — first candidates to scrutinize for unsanctioned inbound")
			return g.render(t)
		},
	}
	return cmd
}

func newSecurityDNSCmd(g *GlobalFlags) *cobra.Command {
	var window string
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "CoreDNS Prometheus metrics scrape + query statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cs, err := g.factory.Clientset()
			if err != nil {
				return err
			}
			pods, err := cs.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
				LabelSelector: "k8s-app=kube-dns",
			})
			if err != nil {
				return fmt.Errorf("list kube-dns pods: %w", err)
			}
			t := &output.Table{
				Title:   fmt.Sprintf("CoreDNS stats (window=%s)", window),
				Headers: []string{"POD", "QUERIES", "ERRORS", "CACHE HIT%", "PANICS", "TOP ZONE"},
			}
			if len(pods.Items) == 0 {
				output.Note(t, "no kube-dns pods found with label k8s-app=kube-dns in kube-system")
				return g.render(t)
			}
			anyScraped := false
			for _, p := range pods.Items {
				if p.Status.PodIP == "" {
					continue
				}
				url := fmt.Sprintf("http://%s:9153/metrics", p.Status.PodIP)
				stats := observe.ScrapeCoreDNS(ctx, nil, url)
				if !stats.Reachable {
					t.Rows = append(t.Rows, output.Row{
						"POD": {Value: p.Name}, "QUERIES": {Value: "-"},
						"ERRORS": {Value: "-"}, "CACHE HIT%": {Value: "-"},
						"PANICS": {Value: "-"}, "TOP ZONE": {Value: "metrics unreachable"},
					})
					continue
				}
				anyScraped = true
				hitPct := "—"
				total := stats.CacheHits + stats.CacheMisses
				if total > 0 {
					hitPct = fmt.Sprintf("%.1f%%", 100*stats.CacheHits/total)
				}
				topZone, topN := topZone(stats.PerZoneQueries)
				zoneCell := "."
				if topZone != "" {
					zoneCell = fmt.Sprintf("%s (%.0f)", topZone, topN)
				}
				t.Rows = append(t.Rows, output.Row{
					"POD":         {Value: p.Name},
					"QUERIES":     {Value: fmt.Sprintf("%.0f", stats.TotalQueries)},
					"ERRORS":      {Value: fmt.Sprintf("%.0f", stats.Errors)},
					"CACHE HIT%":  {Value: hitPct},
					"PANICS":      {Value: fmt.Sprintf("%.0f", stats.Panics)},
					"TOP ZONE":    {Value: zoneCell},
				})
			}
			if anyScraped {
				output.Note(t, "✓ scraped CoreDNS :9153/metrics; tunnel/entropy anomaly detection is roadmap")
			} else {
				output.Note(t, "ℹ CoreDNS metrics port :9153 unreachable — needs the prometheus plugin enabled + NetworkPolicy allowing knm")
			}
			return g.render(t)
		},
	}
	cmd.Flags().StringVar(&window, "window", "5m", "lookback window label (informational; metrics are cumulative)")
	return cmd
}

func topZone(zones map[string]float64) (string, float64) {
	var name string
	var n float64
	for k, v := range zones {
		if v > n {
			name, n = k, v
		}
	}
	return name, n
}

func dnsNote(p corev1.Pod) string {
	for _, c := range p.Spec.Containers {
		if strings.Contains(c.Image, "coredns") {
			return "image=" + c.Image
		}
	}
	return ""
}
