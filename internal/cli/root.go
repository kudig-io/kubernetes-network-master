// Package cli is the cobra command tree for knm-cli. It is intentionally a
// thin layer: each command parses flags, builds the shared kube.Factory, calls
// a pure logic package in internal/*, and renders results via internal/output.
package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/kudig-io/knm-cli/internal/kube"
	"github.com/kudig-io/knm-cli/internal/output"
)

// GlobalFlags holds root-level options shared by every subcommand.
type GlobalFlags struct {
	outputFormat string
	factory      *kube.Factory
	out          io.Writer
	errOut       io.Writer
}

// Execute is the single entry point used by cmd/knm/main.go.
func Execute(args []string) error {
	root, g := newRootCmd()
	root.SetArgs(args)
	root.SetOut(g.out)
	root.SetErr(g.errOut)
	return root.Execute()
}

func newRootCmd() (*cobra.Command, *GlobalFlags) {
	g := &GlobalFlags{
		out:    os.Stdout,
		errOut: os.Stderr,
	}
	root := &cobra.Command{
		Use:   "knm",
		Short: "knm — Kubernetes network master CLI",
		Long: `knm is a single binary for debugging, observing, securing and migrating
Kubernetes networking. It is also installable as the kubectl plugin
` + "`kubectl-net`" + ` so that ` + "`kubectl net <subcommand>`" + ` works.

Examples:
  knm trace pod/web svc/api
  knm policy simulate --policy deny.yaml --src pod/app --dst pod/db --port 5432
  knm gateway migrate -f ingress.yaml -o yaml
  knm depgraph -o mermaid

Global flags mirror kubectl (--kubeconfig, --context, -n, -A, --as, ...).
Output format is controlled with -o table|wide|json|yaml|dot|mermaid.
`,
		SilenceUsage: true,
		// Completion is handled by the completion subcommand below.
		CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: false},
	}
	root.PersistentFlags().StringVarP(&g.outputFormat, "output", "o", "table",
		"Output format: table|wide|json|yaml|dot|mermaid")
	root.PersistentFlags().BoolP("all-namespaces", "A", false,
		"If present, list/scan resources across all namespaces")

	// Wire kubectl-style kubeconfig flags into the root persistent set.
	g.factory = kube.NewFactory(nil)
	g.factory.AddFlags(root.PersistentFlags())

	root.AddCommand(
		newTraceCmd(g),
		newPolicyCmd(g),
		newObserveCmd(g),
		newGatewayCmd(g),
		newCNICmd(g),
		newSecurityCmd(g),
		newMCCmd(g),
		newGPUCmd(g),
		newSandboxCmd(g),
		newDepgraphCmd(g),
		newVersionCmd(),
	)
	return root, g
}

// format resolves the requested output format.
func (g *GlobalFlags) format() output.Format { return output.ParseFormat(g.outputFormat) }

// render is a convenience wrapper around output.Render writing to stdout.
func (g *GlobalFlags) render(t *output.Table) error {
	return output.Render(g.out, t, g.format())
}

// fail is a tiny helper to return a formatted error (root prints "Error:").
func fail(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}

// requireArgs validates an exact/min arg count and returns a friendly error.
func requireArgs(args []string, exact int, usage string) error {
	if len(args) != exact {
		return fmt.Errorf("expected %d argument(s), got %d\nUsage: %s", exact, len(args), usage)
	}
	return nil
}
