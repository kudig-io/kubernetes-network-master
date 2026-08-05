package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	gwint "github.com/kudig-io/knm-cli/internal/gateway"
	"github.com/kudig-io/knm-cli/internal/output"
)

func newGatewayCmd(g *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Gateway API migration, linting, and traffic replay",
		Long: `Tools for adopting the Kubernetes Gateway API.

  migrate  translate Ingress → Gateway + HTTPRoute, with a diff report
  lint     validate Gateway API resources for common misconfigurations
  replay   (roadmap) replay recorded traffic against a new Gateway config`,
	}
	cmd.AddCommand(newGatewayMigrateCmd(g), newGatewayLintCmd(g), newGatewayReplayCmd(g))
	return cmd
}

func newGatewayMigrateCmd(g *GlobalFlags) *cobra.Command {
	var inFile string
	cmd := &cobra.Command{
		Use:   "migrate -f ingress.yaml",
		Short: "Convert Ingress resources into Gateway + HTTPRoute with a diff report",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inFile == "" {
				return fail("provide Ingress with -f FILE (may contain multiple docs)")
			}
			raw, err := os.ReadFile(inFile)
			if err != nil {
				return fmt.Errorf("read %s: %w", inFile, err)
			}
			ings, err := gwint.LoadIngresses(raw)
			if err != nil {
				return err
			}
			mig, err := gwint.Migrate(ings, gwint.Options{})
			if err != nil {
				return err
			}
			// Render generated Gateway + HTTPRoutes as YAML.
			out := map[string]interface{}{}
			if mig.Gateway != nil {
				gj, _ := yaml.Marshal(mig.Gateway)
				out["gateway.yaml"] = string(gj)
			}
			var rts []string
			for _, r := range mig.HTTPRoutes {
				rj, _ := yaml.Marshal(r)
				rts = append(rts, string(rj))
			}
			out["httproutes.yaml"] = rts

			switch g.format() {
			case output.FormatJSON, output.FormatYAML:
				return g.render(&output.Table{Title: "migrate output", Rows: []output.Row{{"result": {Value: fmt.Sprintf("%v", out)}}}})
			default:
				fmt.Fprintln(g.out, "# === Gateway ===")
				if mig.Gateway != nil {
					b, _ := yaml.Marshal(mig.Gateway)
					fmt.Fprintln(g.out, string(b))
				}
				fmt.Fprintln(g.out, "# === HTTPRoutes ===")
				for _, r := range mig.HTTPRoutes {
					b, _ := yaml.Marshal(r)
					fmt.Fprintln(g.out, string(b))
				}
			}

			// Diff report table.
			t := &output.Table{Title: "migration diff", Headers: []string{"SOURCE", "TARGET", "ACTION", "DETAIL"}}
			for _, d := range mig.Diff {
				t.Rows = append(t.Rows, output.Row{
					"SOURCE": {Value: d.Source}, "TARGET": {Value: d.Target},
					"ACTION": {Value: d.Action}, "DETAIL": {Value: d.Detail},
				})
			}
			for _, w := range mig.Warnings {
				output.Note(t, "⚠ %s", w)
			}
			return g.render(t)
		},
	}
	cmd.Flags().StringVarP(&inFile, "filename", "f", "", "Ingress YAML file to migrate")
	return cmd
}

func newGatewayLintCmd(g *GlobalFlags) *cobra.Command {
	var inFile string
	cmd := &cobra.Command{
		Use:   "lint -f gateway-api.yaml",
		Short: "Lint Gateway API resources for misconfigurations",
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no file given, lint live Gateway API resources in the cluster.
			if inFile != "" {
				raw, err := os.ReadFile(inFile)
				if err != nil {
					return fmt.Errorf("read %s: %w", inFile, err)
				}
				set, err := gwint.LoadGatewayAPISet(raw)
				if err != nil {
					return err
				}
				return renderFindings(g, gwint.Lint(set))
			}
			// Live mode.
			ctx := context.Background()
			dyn, err := g.factory.Dynamic()
			if err != nil {
				return err
			}
			gvrGateway := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
			gvrRoute := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
			allNs, _ := cmd.Flags().GetBool("all-namespaces")
			ns, _ := g.factory.Namespace(allNs)
			gwList, err := dyn.Resource(gvrGateway).Namespace(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list gateways: %w", err)
			}
			rtList, err := dyn.Resource(gvrRoute).Namespace(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list httproutes: %w", err)
			}
			set := gwint.LintSet{}
			for _, u := range gwList.Items {
				var gw unstructuredToGateway
				gw.fromUnstructured(&u)
				set.Gateways = append(set.Gateways, gw.gw)
			}
			for _, u := range rtList.Items {
				var rt unstructuredToRoute
				rt.fromUnstructured(&u)
				set.HTTPRoutes = append(set.HTTPRoutes, rt.rt)
			}
			return renderFindings(g, gwint.Lint(set))
		},
	}
	cmd.Flags().StringVarP(&inFile, "filename", "f", "", "Gateway API YAML to lint (omit to lint the live cluster)")
	return cmd
}

func newGatewayReplayCmd(g *GlobalFlags) *cobra.Command {
	var (
		inFile   string
		target   string
		format   string
		timeout  time.Duration
		latency  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "replay -f access.log --target URL",
		Short: "Replay recorded traffic against a new Gateway URL and diff responses",
		Long: `Record production traffic, replay it against a staging Gateway URL, and
compare responses. Input may be an nginx/combined access log (status/latency
compared when the log includes request_time) or a HAR file (--format=har).

Each recorded request is rewritten onto --target (path+query preserved, host
swapped), so you can replay prod traffic against a new Gateway in staging
without DNS changes. The report flags status-code diffs and latency regressions.`,
		Example: `  knm gateway replay -f access.log --target http://gateway.staging:8080
  knm gateway replay -f trace.har --target http://gw.svc:8080 --format har
  knm gateway replay -f access.log --target http://gw --latency-band 200ms`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inFile == "" || target == "" {
				return fail("provide --filename and --target")
			}
			raw, err := os.ReadFile(inFile)
			if err != nil {
				return fmt.Errorf("read %s: %w", inFile, err)
			}
			var reqs []gwint.RecordedRequest
			var resps []gwint.RecordedResponse
			var skipped int
			switch strings.ToLower(format) {
			case "har":
				reqs, resps, skipped, err = gwint.ParseHAR(raw)
			default:
				reqs, resps, skipped, err = gwint.ParseAccessLog(string(raw))
			}
			if err != nil {
				return err
			}
			if len(reqs) == 0 {
				return fail("no requests parsed from %s (skipped %d)", inFile, skipped)
			}
			rep := gwint.Replay(context.Background(), reqs, resps, gwint.ReplayConfig{
				Target: target, Timeout: timeout, LatencyBand: latency,
			})

			t := &output.Table{
				Title:   fmt.Sprintf("gateway replay → %s (%d requests)", target, rep.Total),
				Headers: []string{"METHOD", "PATH", "STATUS", "REPLAY", "VERDICT", "DETAIL"},
			}
			for _, r := range rep.Results {
				t.Rows = append(t.Rows, output.Row{
					"METHOD": {Value: r.Request.Method},
					"PATH":   {Value: r.Request.Path},
					"STATUS": {Value: fmt.Sprintf("%d", r.Expected.StatusCode)},
					"REPLAY": {Value: fmt.Sprintf("%d", r.Replayed.StatusCode)},
					"VERDICT": {Value: r.Status},
					"DETAIL": {Value: r.Detail},
				})
			}
			output.Note(t, "matched=%d  status-diff=%d  latency-diff=%d  errors=%d  skipped=%d",
				rep.Matched, rep.StatusDiffs, rep.LatencyDiffs, rep.Errors, skipped)
			return g.render(t)
		},
	}
	cmd.Flags().StringVarP(&inFile, "filename", "f", "", "recorded traffic: nginx access log (default) or HAR")
	cmd.Flags().StringVar(&target, "target", "", "base URL of the new Gateway to replay against")
	cmd.Flags().StringVar(&format, "format", "accesslog", "input format: accesslog|har")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "per-request replay timeout")
	cmd.Flags().DurationVar(&latency, "latency-band", 100*time.Millisecond, "|replayed-expected| above this flags a latency-diff")
	return cmd
}

func renderFindings(g *GlobalFlags, findings []gwint.Finding) error {
	t := &output.Table{Title: "Gateway API lint findings", Headers: []string{"SEVERITY", "RESOURCE", "FIELD", "MESSAGE"}}
	for _, f := range findings {
		t.Rows = append(t.Rows, output.Row{
			"SEVERITY": {Value: string(f.Severity)},
			"RESOURCE": {Value: f.Resource},
			"FIELD":    {Value: f.Field},
			"MESSAGE":  {Value: f.Message},
		})
	}
	if len(findings) == 0 {
		output.Note(t, "no findings — Gateway API config looks clean to the implemented checks")
	}
	return g.render(t)
}

// unstructuredToGateway / unstructuredToRoute shallow converters. For a deep impl
// we'd use the gateway-api typed client; the dynamic client returns
// *unstructured.Unstructured which we round-trip through JSON.
type unstructuredToGateway struct{ gw gwapiv1.Gateway }
type unstructuredToRoute struct{ rt gwapiv1.HTTPRoute }

func (u *unstructuredToGateway) fromUnstructured(o *unstructured.Unstructured) {
	raw, _ := o.MarshalJSON()
	_ = yaml.Unmarshal(raw, &u.gw) // JSON is valid YAML
}
func (u *unstructuredToRoute) fromUnstructured(o *unstructured.Unstructured) {
	raw, _ := o.MarshalJSON()
	_ = yaml.Unmarshal(raw, &u.rt)
}
