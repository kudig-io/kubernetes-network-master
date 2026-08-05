package cli

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/kudig-io/knm-cli/internal/output"
)

func newSandboxCmd(g *GlobalFlags) *cobra.Command {
	var (
		runtime string
		name    string
		create  bool
		delete_ bool
	)
	defaultName := "knm-sandbox"
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Spin up / tear down a local Kubernetes network sandbox (kind/k3d)",
		Long: `Manage a local throwaway cluster for learning and testing knm against multiple
CNIs. Detects kind or k3d; with --create it brings up a named cluster.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				name = defaultName
			}
			tool := pickRuntime(runtime)
			t := &output.Table{
				Title:   "knm network sandbox",
				Headers: []string{"RUNTIME", "FOUND", "ACTION", "RESULT"},
			}
			if tool == "" {
				t.Rows = append(t.Rows, output.Row{
					"RUNTIME": {Value: "kind/k3d"}, "FOUND": {Value: "no"},
					"ACTION": {Value: "install one to use the sandbox"},
					"RESULT": {Value: "see https://kind.sigs.k8s.io or https://k3d.io"},
				})
				output.NYI(t, "auto-install kind/k3d + guided multi-CNI comparison tutorial")
				return g.render(t)
			}
			if _, err := exec.LookPath(tool); err != nil {
				t.Rows = append(t.Rows, output.Row{
					"RUNTIME": {Value: tool}, "FOUND": {Value: "no (not in PATH)"},
					"ACTION": {Value: "install " + tool}, "RESULT": {Value: "-"},
				})
				return g.render(t)
			}

			switch {
			case delete_:
				out, err := runTool(tool, "delete", "cluster", "--name", name)
				result := "deleted"
				if err != nil {
					result = "error: " + err.Error()
				}
				t.Rows = append(t.Rows, output.Row{
					"RUNTIME": {Value: tool}, "FOUND": {Value: "yes"},
					"ACTION": {Value: fmt.Sprintf("%s delete cluster --name %s", tool, name)},
					"RESULT": {Value: result, Wide: out},
				})
			case create:
				args := []string{"create", "cluster", "--name", name}
				if tool == "k3d" {
					// k3d uses a different create syntax.
					args = []string{"cluster", "create", name}
				}
				out, err := runTool(tool, args...)
				result := "created"
				if err != nil {
					result = "error: " + err.Error()
				}
				t.Rows = append(t.Rows, output.Row{
					"RUNTIME": {Value: tool}, "FOUND": {Value: "yes"},
					"ACTION": {Value: fmt.Sprintf("%s %v", tool, args)},
					"RESULT": {Value: result, Wide: out},
				})
				output.Note(t, "ℹ multi-CNI swap + interactive tutorial is roadmap; the cluster is ready for `knm trace` etc.")
			default:
				t.Rows = append(t.Rows, output.Row{
					"RUNTIME": {Value: tool}, "FOUND": {Value: "yes"},
					"ACTION": {Value: fmt.Sprintf("--create to bring up cluster %q / --delete to tear down", name)},
					"RESULT": {Value: "ready"},
				})
			}
			return g.render(t)
		},
	}
	cmd.Flags().StringVar(&runtime, "runtime", "", "cluster runtime: kind|k3d (autodetected if empty)")
	cmd.Flags().StringVar(&name, "name", defaultName, "cluster name")
	cmd.Flags().BoolVar(&create, "create", false, "create the cluster now")
	cmd.Flags().BoolVar(&delete_, "delete", false, "delete the cluster")
	return cmd
}

// runTool executes the cluster runtime and returns combined output.
func runTool(tool string, args ...string) (string, error) {
	c := exec.Command(tool, args...)
	out, err := c.CombinedOutput()
	return string(out), err
}

func pickRuntime(pref string) string {
	if pref == "kind" || pref == "k3d" {
		return pref
	}
	for _, c := range []string{"kind", "k3d"} {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return ""
}
