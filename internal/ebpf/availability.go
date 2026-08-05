// Package ebpf reports whether eBPF-based features can run in the current
// process environment.
//
// This is intentionally dependency-free: the real probe/bytecode lives behind
// a build-tagged stub that we only compile on Linux. On other platforms
// (or when privileges are missing) commands gracefully degrade instead of
// crashing. See docs/ebpf.md for the roadmap to a real libbpf-go backend.
package ebpf

import (
	"runtime"
)

// Status describes why eBPF is or is not available.
type Status struct {
	Available bool
	Reason    string // empty when Available is true
}

// String renders a human-friendly reason.
func (s Status) String() string {
	if s.Available {
		return "eBPF available"
	}
	return "eBPF unavailable: " + s.Reason
}

// Availability probes the runtime environment. The current build always
// reports unavailable on non-Linux platforms and "no real probe yet" on Linux
// (the libbpf backend is not wired in — see roadmap). Callers should branch
// on Available and, when false, present a Degrade path.
func Availability() Status {
	if runtime.GOOS != "linux" {
		return Status{Available: false, Reason: "eBPF requires a Linux kernel; current OS is " + runtime.GOOS}
	}
	// Linux: we still can't claim availability without the libbpf backend +
	// capability checks. Report a clear reason so commands degrade cleanly.
	return Status{Available: false, Reason: "knm eBPF backend not enabled in this build (see docs/ebpf.md)"}
}

// Degrade returns a pointer to a reason string that commands can surface when
// they must fall back to an API-level implementation. It is nil-friendly: pass
// it the feature name to get a tailored message.
func Degrade(feature string) string {
	s := Availability()
	if s.Available {
		return ""
	}
	return "feature '" + feature + "' needs eBPF; " + s.Reason + " — falling back to API-level data"
}
