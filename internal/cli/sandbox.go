package cli

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/kudig-io/knm-cli/internal/output"
)

func newSandboxCmd(g *GlobalFlags) *cobra.Command {
	var runtime string
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Spin up a local Kubernetes network sandbox (kind/k3d) with multiple CNIs",
		RunE: func(cmd *cobra.Command, args []string) error {
			tool := pickRuntime(runtime)
			t := &output.Table{
				Title:   "knm network sandbox",
				Headers: []string{"RUNTIME", "FOUND", "ACTION"},
			}
			if tool == "" {
				t.Rows = append(t.Rows, output.Row{
					"RUNTIME": {Value: "kind/k3d"}, "FOUND": {Value: "no"}, "ACTION": {Value: "install kind or k3d first"},
				})
				output.NYI(t, "auto-install kind/k3d and a guided CNI comparison tutorial")
				return g.render(t)
			}
			if _, err := exec.LookPath(tool); err != nil {
				t.Rows = append(t.Rows, output.Row{
					"RUNTIME": {Value: tool}, "FOUND": {Value: "no (not in PATH)"}, "ACTION": {Value: "install " + tool},
				})
				return g.render(t)
			}
			t.Rows = append(t.Rows, output.Row{
				"RUNTIME": {Value: tool}, "FOUND": {Value: "yes"}, "ACTION": {Value: fmt.Sprintf("would run: %s create cluster ...", tool)},
			})
			output.NYI(t, "one-click multi-CNI cluster bring-up + interactive tutorial")
			return g.render(t)
		},
	}
	cmd.Flags().StringVar(&runtime, "runtime", "", "cluster runtime to use: kind|k3d (autodetected if empty)")
	return cmd
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
