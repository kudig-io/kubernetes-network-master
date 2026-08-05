// Command knm is the Kubernetes network master CLI.
//
// It is also installable as the kubectl plugin `kubectl-net`: when invoked
// under the argv[0] name "kubectl-net", the root command relabels itself so
// `kubectl net trace ...` works as expected.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kudig-io/knm-cli/internal/cli"
)

func main() {
	// Detect kubectl plugin invocation: argv[0] basename == "kubectl-net".
	// In that mode kubectl passes the subcommand word "net" as argv[1]; we
	// strip it so the cobra tree lines up.
	args := os.Args[1:]
	if isKubectlPlugin(os.Args[0]) && len(args) > 0 && args[0] == "net" {
		args = args[1:]
	}
	if err := cli.Execute(args); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func isKubectlPlugin(argv0 string) bool {
	base := filepath.Base(argv0)
	// Also cover ".exe" on Windows.
	base = strings.TrimSuffix(base, ".exe")
	return base == "kubectl-net"
}
