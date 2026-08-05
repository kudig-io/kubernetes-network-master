package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kudig-io/knm-cli/internal/kube"
	"github.com/kudig-io/knm-cli/internal/output"
	"github.com/kudig-io/knm-cli/internal/trace"
)

func newTraceCmd(g *GlobalFlags) *cobra.Command {
	var (
		port           int32
		probe          string
		tcpTimeout     time.Duration
		noExec         bool
		inspectRules   bool
		mtuProbe       bool
		debugContainer bool
	)
	cmd := &cobra.Command{
		Use:   "trace SRC DST",
		Short: "Trace the full network path from a source Pod to a target Service/Pod",
		Long: `Trace the end-to-end network path Kubernetes applies between two workloads.

The source must be a Pod (pod/name or ns/pod/name). The destination may be a
Service (svc/name or name) or a Pod. knm walks the chain a real packet
traverses, marking the first broken hop:

  1. Source Pod     — Running, Ready, IP assigned
  2. DNS            — cluster DNS present AND actively resolves the target name
  3. NetworkPolicy  — static src→dst allow/deny verdict (policy engine)
  4. Service        — exists, type, ClusterIP, port inference
  5. Endpoints      — ready backing pods
  6. TCP Connect    — active handshake from source Pod to backend :port
  7. kube-proxy     — mode detection (iptables/ipvs/ebpf)
  8. CNI            — detected CNI, same-node vs cross-node
  9. Target Pod     — IP, node, readiness

Active probes (DNS resolve, TCP connect) run inside the source Pod via exec and
auto-detect available tools (getent/nslookup, nc/bash/wget/curl). When exec is
unavailable (--no-exec, no pods/exec RBAC, or a stripped image) those hops
degrade to SKIP/WARN instead of failing. Use --probe=api for a pure read-only
walk (CI-friendly).

Render the hop chain as a path graph with -o dot or -o mermaid.
`,
		Example: `  knm trace pod/web svc/api
  knm trace pod/web pod/db -n app --port 5432
  knm trace default/web default/api --port 80 --probe=api
  knm trace pod/web svc/api -o mermaid`,
		Args:         func(cmd *cobra.Command, args []string) error { return requireArgs(args, 2, "knm trace SRC DST") },
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cs, err := g.factory.Clientset()
			if err != nil {
				return err
			}
			src, err := parseRef(args[0], g)
			if err != nil {
				return err
			}
			dst, err := parseRef(args[1], g)
			if err != nil {
				return err
			}

			// Pick the exec client: --no-exec or --probe=api disables exec.
			exec, execNote := resolveExec(g, noExec, probe)
			mode := parseProbeMode(probe)

			// Ephemeral injector is only built when --debug-container is set
			// (it needs ephemeralcontainers RBAC + cluster access).
			var inj trace.EphemeralInjector
			if debugContainer && !noExec && !strings.EqualFold(probe, "api") {
				inj = kube.NewEphemeralInjector(g.factory)
			}

			ns, _ := g.factory.Namespace(false)
			res := trace.Run(ctx, cs, exec, toTraceRef(src, ns), toTraceRef(dst, ns), trace.Options{
				Probe:            mode,
				TCPConnectWait:   tcpTimeout,
				Port:             port,
				DefaultNamespace: ns,
				InspectRules:     inspectRules,
				MTUProbe:         mtuProbe,
				DebugContainer:   debugContainer,
				Injector:         inj,
			})

			// Build the output table.
			t := &output.Table{
				Title:   fmt.Sprintf("trace %s → %s", args[0], args[1]),
				Headers: []string{"STAGE", "STATUS", "DETAIL"},
			}
			for _, h := range res.Hops {
				t.Rows = append(t.Rows, output.Row{
					"STAGE":  {Value: h.Stage},
					"STATUS": {Value: string(h.Status), Wide: h.Note},
					"DETAIL": {Value: h.Detail},
				})
			}
			// Path graph for -o dot / -o mermaid.
			t.Graph = hopGraph(res.Hops, args[0]+" → "+args[1])

			// Summary notes.
			if res.Broken() {
				output.Note(t, "✗ path is broken at the first FAIL hop above")
			} else {
				output.Note(t, "✓ no break detected in the walked chain")
			}
			if execNote != "" {
				output.Note(t, "ℹ %s", execNote)
			}
			output.Note(t, "ℹ kube-proxy rule inspection, CNI datapath probe, path-MTU discovery are roadmap items")
			return g.render(t)
		},
	}
	cmd.Flags().Int32Var(&port, "port", 0, "target port (optional; inferred from Service when omitted)")
	cmd.Flags().StringVar(&probe, "probe", "auto", "probe mode: auto|api|tcp|dns (api = read-only walk, no exec)")
	cmd.Flags().DurationVar(&tcpTimeout, "tcpconnect-timeout", 2*time.Second, "TCP connect probe timeout")
	cmd.Flags().BoolVar(&noExec, "no-exec", false, "skip all in-pod exec probes (equivalent to --probe=api)")
	cmd.Flags().BoolVar(&inspectRules, "inspect-rules", false, "exec kube-proxy pod to check the ClusterIP has a data-plane rule (ipvs/iptables/nft)")
	cmd.Flags().BoolVar(&mtuProbe, "mtu-probe", false, "run a DF-ping path-MTU discovery from the source Pod to the target")
	cmd.Flags().BoolVar(&debugContainer, "debug-container", false, "inject an ephemeral debug container (for stripped/distroless images; needs ephemeralcontainers RBAC)")
	return cmd
}

// resolveExec returns the ExecClient to use and a human note explaining any
// disablement. --no-exec and --probe=api both disable exec.
func resolveExec(g *GlobalFlags, noExec bool, probe string) (trace.ExecClient, string) {
	if noExec || strings.EqualFold(probe, "api") {
		return trace.NoExec, "exec probes disabled (--no-exec or --probe=api); active hops degraded to SKIP"
	}
	return kube.NewRemoteExecutor(g.factory), ""
}

func parseProbeMode(s string) trace.ProbeMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "api", "read-only":
		return trace.ProbeAPI
	case "tcp":
		return trace.ProbeTCP
	case "dns":
		return trace.ProbeDNS
	default:
		return trace.ProbeAuto
	}
}

// toTraceRef converts the cli-level traceRef into a trace.Ref, defaulting the
// namespace from the effective -n when unset.
func toTraceRef(r traceRef, defaultNS string) trace.Ref {
	ns := r.namespace
	if ns == "" {
		ns = defaultNS
	}
	return trace.Ref{Kind: toTraceKind(r.kind), Namespace: ns, Name: r.name}
}

func toTraceKind(k refKind) trace.RefKind {
	if k == refPod {
		return trace.RefPod
	}
	return trace.RefService
}

// hopGraph builds a left-to-right path graph from the hop chain for dot/mermaid.
// FAIL nodes get a distinct note so the renderer can highlight them.
func hopGraph(hops []trace.Hop, label string) *output.Graph {
	g := &output.Graph{Label: label}
	prev := ""
	for i, h := range hops {
		id := hopNodeID(i, h)
		g.Nodes = append(g.Nodes, output.GraphNode{
			ID:    id,
			Label: h.Stage,
			Kind:  string(h.Status),
		})
		if prev != "" {
			edgeLabel := ""
			if h.Status == trace.StatusFail {
				edgeLabel = "broken"
			}
			g.Edges = append(g.Edges, output.GraphEdge{From: prev, To: id, Label: edgeLabel})
		}
		prev = id
	}
	return g
}

func hopNodeID(i int, h trace.Hop) string {
	// Mermaid/IDs can't contain spaces; sanitize.
	base := strings.ToLower(strings.ReplaceAll(h.Stage, " ", "_"))
	return fmt.Sprintf("%02d_%s", i, base)
}

// --- shared helpers also used by other commands ---

// refKind enumerates the references knm trace understands.
type refKind int

const (
	refPod refKind = iota
	refService
)

type traceRef struct {
	kind      refKind
	namespace string
	name      string
}

// parseRef accepts pod/NAME, svc/NAME, NAME, NS/NAME, or NS/pod/NAME.
func parseRef(s string, g *GlobalFlags) (traceRef, error) {
	ns, _ := g.factory.Namespace(false)
	parts := strings.Split(s, "/")
	switch len(parts) {
	case 1:
		// bare name → assume Service (most common for DST)
		return traceRef{kind: refService, namespace: ns, name: parts[0]}, nil
	case 2:
		switch strings.ToLower(parts[0]) {
		case "pod", "pods":
			return traceRef{kind: refPod, namespace: ns, name: parts[1]}, nil
		case "svc", "service", "services":
			return traceRef{kind: refService, namespace: ns, name: parts[1]}, nil
		default:
			return traceRef{kind: refService, namespace: parts[0], name: parts[1]}, nil
		}
	case 3:
		ns = parts[0]
		switch strings.ToLower(parts[1]) {
		case "pod", "pods":
			return traceRef{kind: refPod, namespace: ns, name: parts[2]}, nil
		case "svc", "service", "services":
			return traceRef{kind: refService, namespace: ns, name: parts[2]}, nil
		}
	}
	return traceRef{}, fmt.Errorf("could not parse reference %q (try pod/name, svc/name, ns/name)", s)
}

// keep metav1 referenced (used by future hop enrichers in this package).
var _ = metav1.GetOptions{}
