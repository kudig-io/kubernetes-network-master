package kube

import (
	"bytes"
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// RemoteExecutor runs commands inside a Pod via the Kubernetes exec API
// (SPDY/WebSocket). It implements trace.ExecClient.
//
// Construction needs a *rest.Config (from Factory.Config()) and a typed
// clientset for URL building. The exec layer is the only place knm needs
// elevated access (pods/exec), which is why it is isolated behind the
// trace.ExecClient interface.
type RemoteExecutor struct {
	ClientGetter func() (*rest.Config, error)
}

// NewRemoteExecutor builds an executor backed by the given Factory's rest config.
func NewRemoteExecutor(f *Factory) *RemoteExecutor {
	return &RemoteExecutor{ClientGetter: f.Config}
}

// Run executes cmd inside namespace/pod (container = the pod's first container
// if multiple) and returns captured stdout/stderr, the exit code (parsed from
// the remote error when available), and any transport error.
//
// Exit code semantics: Kubernetes exec returns an exec.ExitError embedded in
// the SPDY error stream when the process exits non-zero. remotecommand surfaces
// it via the returned error; we parse the code, defaulting to 127 when we can't
// determine it.
func (e *RemoteExecutor) Run(ctx context.Context, namespace, pod string, cmd []string, timeout time.Duration) (string, string, int, error) {
	cfg, err := e.ClientGetter()
	if err != nil {
		return "", "", 0, fmt.Errorf("get rest config: %w", err)
	}
	cli, err := kubernetesNewForConfig(cfg)
	if err != nil {
		return "", "", 0, fmt.Errorf("build clientset for exec: %w", err)
	}

	// Pick the first container if the pod has several; empty string means
	// "the pod's only container" which the API accepts.
	podObj, err := cli.CoreV1().Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
	container := ""
	if err == nil {
		for _, c := range podObj.Spec.Containers {
			if c.Name != "" {
				container = c.Name
				break
			}
		}
		// Refuse to exec into a pod that isn't running.
		if podObj.Status.Phase != corev1.PodRunning {
			return "", "", 0, fmt.Errorf("pod %s/%s not running (phase=%s)", namespace, pod, podObj.Status.Phase)
		}
	}

	req := cli.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(pod).
		SubResource("exec")
	req.VersionedParams(&corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return "", "", 0, fmt.Errorf("build exec executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	runCtx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	err = executor.StreamWithContext(runCtx, remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	code := 0
	if err != nil {
		code = parseExecExitCode(err, stderr.String())
	}
	return stdout.String(), stderr.String(), code, err
}

// kubernetesNewForConfig is a thin local wrapper so this file's only direct
// clientset import stays here (the Factory already caches one, but exec needs
// its own for URL building — cheap).
func kubernetesNewForConfig(cfg *rest.Config) (kubernetes.Interface, error) {
	return kubernetes.NewForConfig(cfg)
}

// parseExecExitCode tries to recover the process exit code from the error
// returned by remotecommand.Stream. The exec subresource encodes non-zero
// exits as an error of the form "... command terminated with exit code N".
// We default to 127 ("command not found" style) when no code is found.
func parseExecExitCode(err error, stderr string) int {
	msg := err.Error() + " " + stderr
	// "command terminated with exit code 5"
	if idx := indexOfStr(msg, "exit code "); idx >= 0 {
		rest := msg[idx+len("exit code "):]
		n := 0
		for _, ch := range rest {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		if n > 0 {
			return n
		}
	}
	return 127
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// EphemeralInjector attaches a debug container to a Pod via the
// ephemeralcontainers subresource. It implements trace.EphemeralInjector.
type EphemeralInjector struct {
	ClientGetter func() (*rest.Config, error)
}

// NewEphemeralInjector builds an injector backed by the Factory's rest config.
func NewEphemeralInjector(f *Factory) *EphemeralInjector {
	return &EphemeralInjector{ClientGetter: f.Config}
}

// Inject attaches an ephemeral container running `image` to the named Pod. The
// container sleeps so it stays alive for the user to exec into. Returns the
// chosen container name. Requires the ephemeralcontainers RBAC subresource.
func (e *EphemeralInjector) Inject(ctx context.Context, namespace, pod, image string) (string, error) {
	cfg, err := e.ClientGetter()
	if err != nil {
		return "", fmt.Errorf("get rest config: %w", err)
	}
	cli, err := kubernetesNewForConfig(cfg)
	if err != nil {
		return "", fmt.Errorf("build clientset for inject: %w", err)
	}
	// Fetch the current pod so we append rather than overwrite.
	current, err := cli.CoreV1().Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get pod: %w", err)
	}
	containerName := "knm-debug"
	// Avoid duplicate-name collisions with existing ephemeral containers.
	for i := 1; ; i++ {
		clash := false
		for _, ec := range current.Spec.EphemeralContainers {
			if ec.Name == containerName {
				clash = true
				break
			}
		}
		if !clash {
			break
		}
		containerName = fmt.Sprintf("knm-debug-%d", i)
		if i > 20 {
			break
		}
	}
	target := current.DeepCopy()
	target.Spec.EphemeralContainers = append(target.Spec.EphemeralContainers, corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:                     containerName,
			Image:                    image,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			Command:                  []string{"sleep", "3600"},
			TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		},
	})
	if _, err := cli.CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, pod, target, metav1.UpdateOptions{}); err != nil {
		return "", fmt.Errorf("update ephemeralcontainers: %w", err)
	}
	return containerName, nil
}
