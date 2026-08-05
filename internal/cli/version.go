package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kudig-io/knm-cli/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print knm version and build info",
		Long:  "Prints the semantic version, commit, and build date injected at compile time.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("knm %s\n", version.String())
			return nil
		},
	}
}
