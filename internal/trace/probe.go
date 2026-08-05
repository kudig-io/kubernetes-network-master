// Package trace implements the knm network path tracer. It is pure logic over
// fetched Kubernetes API objects plus a small ExecClient abstraction for
// in-cluster active probing, so the whole chain is unit-testable without a
// real cluster (see trace_test.go).
//
// The hop chain knm trace walks mirrors what a real packet experiences:
//
//	Source Pod → DNS → NetworkPolicy → Service → Endpoints → TCP Connect
//	              → kube-proxy → CNI → Target Pod
//
// Each hop returns an OK/WARN/FAIL/SKIP verdict; the first FAIL is treated as
// the break point. Active probes (DNS resolve, TCP connect) run inside the
// source Pod via ExecClient and degrade to SKIP/WARN when exec is unavailable
// (--no-exec, RBAC denial, or a stripped image without nc/wget/curl/bash).
package trace

import (
	"context"
	"time"
)

// Status is a hop verdict.
type Status string

const (
	StatusOK   Status = "OK"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

// Hop is one stage in the synthetic path.
type Hop struct {
	Stage  string // Source Pod | DNS | NetworkPolicy | Service | Endpoints | TCP Connect | kube-proxy | CNI | Target Pod
	Detail string
	Status Status
	Note   string // shown in -o wide, or a degrade reason
}

// ProbeMode selects how aggressively knm trace probes the path.
type ProbeMode string

const (
	// ProbeAuto runs active probes when exec is available, else degrades.
	ProbeAuto ProbeMode = "auto"
	// ProbeAPI is read-only API walk only (no exec) — CI-friendly.
	ProbeAPI ProbeMode = "api"
	// ProbeTCP forces TCP connect probing even if auto would skip.
	ProbeTCP ProbeMode = "tcp"
	// ProbeDNS forces DNS resolution probing.
	ProbeDNS ProbeMode = "dns"
)

// ExecClient runs a command inside a Pod and returns captured stdout/stderr,
// the process exit code, and any transport error. The production implementation
// lives in internal/kube (remotecommand SPDY); tests pass a fake.
type ExecClient interface {
	Run(ctx context.Context, namespace, pod string, cmd []string, timeout time.Duration) (stdout, stderr string, code int, err error)
}

// EphemeralInjector attaches an ephemeral debug container to a Pod. The
// production implementation lives in internal/kube (UpdateEphemeralContainers);
// tests pass a fake. Returns the container name on success.
type EphemeralInjector interface {
	Inject(ctx context.Context, namespace, pod string, image string) (containerName string, err error)
}

// DebugContainerImage is the default ephemeral container image knm injects.
// netshoot bundles nc, curl, iperf3, ping, dig, tcpdump, etc.
const DebugContainerImage = "nicolaka/netshoot:latest"

// noExecClient is the ExecClient used when --no-exec is set or exec is globally
// disabled; every Run returns a sentinel error that hops translate to SKIP.
type noExecClient struct{}

func (noExecClient) Run(_ context.Context, _, _ string, _ []string, _ time.Duration) (string, string, int, error) {
	return "", "", 0, errNoExec
}

// NoExec is a shared ExecClient that always refuses to run.
var NoExec ExecClient = noExecClient{}
