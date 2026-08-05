package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/yaml"

	"github.com/kudig-io/knm-cli/internal/ebpf"
	"github.com/kudig-io/knm-cli/internal/output"
	netint "github.com/kudig-io/knm-cli/internal/policy"
)

func newPolicyCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "NetworkPolicy simulation, checks, matrix, and generation",
		Long: `Work with Kubernetes NetworkPolicies without needing a specific CNI.

Subcommands:
  check POD      list the policies selecting a Pod and its isolation state
  simulate       pure-static allow/deny verdict for src→dst (no cluster needed)
  matrix         Pod×Pod allow matrix for a namespace
  generate       emit a least-privilege NetworkPolicy (eBPF-observed or default-deny)`,
	}
	cmd.AddCommand(newPolicyCheckCmd(g), newPolicySimulateCmd(g), newPolicyMatrixCmd(g), newPolicyGenerateCmd(g))
	return cmd
}

func newPolicyCheckCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check POD",
		Short: "Show NetworkPolicies selecting a Pod and its ingress/egress isolation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cs, err := g.factory.Clientset()
			if err != nil {
				return err
			}
			ns, _ := g.factory.Namespace(false)
			name := args[0]
			pod, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("get pod: %w", err)
			}
			pols, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list networkpolicies: %w", err)
			}
			t := &output.Table{
				Title:   fmt.Sprintf("NetworkPolicies selecting %s/%s", ns, name),
				Headers: []string{"POLICY", "TYPES", "INGRESS", "EGRESS", "SELECTS POD"},
			}
			podLabels := labels.Set(pod.Labels)
			inIso, egIso := false, false
			for _, p := range pols.Items {
				sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
				if err != nil {
					continue
				}
				matches := sel.Matches(podLabels)
				types := ""
				for _, pt := range p.Spec.PolicyTypes {
					if types != "" {
						types += ","
					}
					types += string(pt)
					if pt == "Ingress" {
						inIso = inIso || matches
					}
					if pt == "Egress" {
						egIso = egIso || matches
					}
				}
				t.Rows = append(t.Rows, output.Row{
					"POLICY":      {Value: p.Name},
					"TYPES":       {Value: types},
					"INGRESS":     {Value: countRules(len(p.Spec.Ingress))},
					"EGRESS":      {Value: countRules(len(p.Spec.Egress))},
					"SELECTS POD": {Value: yesNo(matches)},
				})
			}
			if len(t.Rows) == 0 {
				output.Note(t, "no NetworkPolicies in namespace %s select this pod", ns)
			}
			output.Note(t, "ingress isolated: %s | egress isolated: %s", yesNo(inIso), yesNo(egIso))
			if !inIso && !egIso {
				output.Note(t, "ℹ pod is default-allow (all ingress/egress permitted)")
			}
			return g.render(t)
		},
	}
	return cmd
}

func newPolicySimulateCmd(g *GlobalFlags) *cobra.Command {
	var (
		policyFile string
		port       int32
		proto      string
		srcLabels  string
		dstLabels  string
	)
	cmd := &cobra.Command{
		Use:   "simulate --policy FILE --src REF --dst REF",
		Short: "Pure-static allow/deny verdict for src→dst (no cluster access required)",
		Long: `Evaluate a set of NetworkPolicies against a source→destination pair using
only the static YAML. Useful for CI and "if I apply this, what happens?" checks.

Endpoints may be a bare name (treated as ns/name from -n), ns/name, or an IP.
For name endpoints the labels ` + "`app`" + ` and ` + "`pod`" + ` are auto-seeded to the name so the
common ` + "`app:`" + `-keyed policies match; override with --src-labels/--dst-labels
as comma-separated key=value pairs.
`,
		Example: `  knm policy simulate --policy netpol.yaml --src pod/app --dst pod/db --port 5432
  knm policy simulate --policy netpol.yaml --src ns/app --dst ns/db \
      --src-labels app=web,team=payments --dst-labels app=db,tier=data --port 5432`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if policyFile == "" {
				return fail("--policy is required")
			}
			raw, err := os.ReadFile(policyFile)
			if err != nil {
				return fmt.Errorf("read %s: %w", policyFile, err)
			}
			pols, err := netint.LoadPoliciesFromBytes(raw)
			if err != nil {
				return err
			}
			srcFlag, _ := cmd.Flags().GetString("src")
			dstFlag, _ := cmd.Flags().GetString("dst")
			if srcFlag == "" || dstFlag == "" {
				return fail("--src and --dst are required")
			}
			src, err := netint.ParseEndpoint(srcFlag)
			if err != nil {
				return err
			}
			dst, err := netint.ParseEndpoint(dstFlag)
			if err != nil {
				return err
			}
			mergeLabels(&src, srcLabels)
			mergeLabels(&dst, dstLabels)
			protos := parseProtos(proto)
			eng := netint.NewEngine(pols)
			res := eng.Simulate(netint.Query{Dest: dst, Src: src, DestPort: port, Protos: protos})

			t := &output.Table{
				Title:   fmt.Sprintf("simulate %s → %s :%d", srcFlag, dstFlag, port),
				Headers: []string{"ALLOWED", "INGRESS-ISOLATED", "REASON"},
			}
			t.Rows = append(t.Rows, output.Row{
				"ALLOWED":          {Value: yesNo(res.Allowed)},
				"INGRESS-ISOLATED": {Value: yesNo(res.IngressIsolated)},
				"REASON":           {Value: res.Reason},
			})
			return g.render(t)
		},
	}
	cmd.Flags().StringVar(&policyFile, "policy", "", "NetworkPolicy YAML file (may contain multiple docs)")
	cmd.Flags().String("src", "", "source endpoint: pod, ns/pod, or 1.2.3.4")
	cmd.Flags().String("dst", "", "destination endpoint: pod, ns/pod, or 1.2.3.4")
	cmd.Flags().Int32Var(&port, "port", 0, "destination port")
	cmd.Flags().StringVar(&proto, "proto", "TCP", "L4 protocol (TCP/UDP/SCTP)")
	cmd.Flags().StringVar(&srcLabels, "src-labels", "", "comma-separated key=value labels for the source")
	cmd.Flags().StringVar(&dstLabels, "dst-labels", "", "comma-separated key=value labels for the destination")
	return cmd
}

// mergeLabels parses a comma-separated key=value list and merges it into an
// Endpoint's label set, overriding any auto-seeded values.
func mergeLabels(ep *netint.Endpoint, raw string) {
	if raw == "" {
		return
	}
	if ep.Labels == nil {
		ep.Labels = labels.Set{}
	}
	for _, pair := range splitCSV(raw) {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			ep.Labels[kv[0]] = kv[1]
		}
	}
}

// splitCSV is a tiny comma splitter that ignores empty fields.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func newPolicyMatrixCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "matrix",
		Short: "Pod×Pod ingress allow matrix for the current namespace",
		RunE: func(cmd *cobra.Command, args []string) error {
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
			pols, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return err
			}
			netpols := pols.Items
			names := make([]string, 0, len(pods.Items))
			endpoints := make([]netint.Endpoint, 0, len(pods.Items))
			for _, p := range pods.Items {
				if len(p.Status.PodIP) == 0 {
					continue
				}
				names = append(names, p.Name)
				endpoints = append(endpoints, netint.Endpoint{
					Namespace: p.Namespace, Pod: p.Name,
					IP: p.Status.PodIP, Labels: labels.Set(p.Labels),
				})
			}
			eng := netint.NewEngine(netpols)
			headers := append([]string{"src \\ dst"}, names...)
			t := &output.Table{Title: "NetworkPolicy allow matrix (ingress)", Headers: headers}
			for i, src := range endpoints {
				row := output.Row{"src \\ dst": {Value: names[i]}}
				for j, dst := range endpoints {
					res := eng.Simulate(netint.Query{Dest: dst, Src: src})
					mark := "✗"
					if res.Allowed {
						mark = "✓"
					}
					row[names[j]] = output.Cell{Value: mark}
				}
				t.Rows = append(t.Rows, row)
			}
			if len(pods.Items) > 20 {
				output.Note(t, "ℹ namespace has %d pods; matrix truncated rendering still works but is wide", len(pods.Items))
			}
			return g.render(t)
		},
	}
	return cmd
}

func newPolicyGenerateCmd(g *GlobalFlags) *cobra.Command {
	var (
		defaultDenyOnly bool
		fromFlows       string
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a least-privilege NetworkPolicy (eBPF-observed or default-deny)",
		Long: `Without --from-flows, emits a default-deny-all baseline policy.

With --from-flows FILE, ingests an observed-flow dump (the future eBPF observer
output) and synthesizes least-privilege egress rules grouped by source
namespace. Real eBPF capture is a roadmap item; today you can author the flow
file by hand or from existing logs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ns, _ := g.factory.Namespace(false)
			// Document the eBPF availability regardless of path.
			ebpfStatus := ebpf.Availability()
			if !defaultDenyOnly && fromFlows == "" {
				// Default behavior: emit default-deny.
				np := netint.DefaultDenyAll(ns, "")
				b, _ := yaml.Marshal(np)
				fmt.Fprintln(g.out, string(b))
				output.NYI(&output.Table{}, "eBPF-based flow observation to auto-populate least-privilege rules; "+ebpfStatus.String())
				return nil
			}
			if fromFlows != "" {
				flows, err := netint.LoadFlowsFromBytes([]byte(fromFlows))
				if err != nil {
					return err
				}
				pols := netint.LeastPrivilege(flows)
				for _, p := range pols {
					b, _ := yaml.Marshal(p)
					fmt.Fprintln(g.out, string(b))
				}
				if ebpfStatus.Reason != "" {
					output.NYI(&output.Table{}, "live eBPF flow capture; loaded flows from --from-flows ("+ebpfStatus.Reason+")")
				}
				return nil
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&defaultDenyOnly, "default-deny", false, "emit a default-deny-all baseline (no egress rules)")
	cmd.Flags().StringVar(&fromFlows, "from-flows", "", "path/YAML of observed flows to synthesize least-privilege egress")
	return cmd
}

// --- small helpers ---

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func countRules(n int) string {
	if n == 0 {
		return "0 (deny-all in scope)"
	}
	return fmt.Sprintf("%d", n)
}

func parseProtos(s string) []corev1.Protocol {
	switch s {
	case "UDP":
		return []corev1.Protocol{corev1.ProtocolUDP}
	case "SCTP":
		return []corev1.Protocol{corev1.ProtocolSCTP}
	default:
		return []corev1.Protocol{corev1.ProtocolTCP}
	}
}
