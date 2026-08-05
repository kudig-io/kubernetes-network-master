// Package version holds build-time version metadata injected via -ldflags.
package version

import "fmt"

var (
	// Version is the semantic version (e.g. git describe). "dev" if unset.
	Version = "dev"
	// Commit is the short git SHA.
	Commit = "unknown"
	// BuildDate is the UTC build timestamp (RFC3339).
	BuildDate = "unknown"
)

// Info is the structured version payload.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

// Get returns the current version Info.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
}

// String returns a one-line human version string.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
}
