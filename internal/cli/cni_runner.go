package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"

	"github.com/kudig-io/knm-cli/internal/cni"
	"github.com/kudig-io/knm-cli/internal/kube"
)

// k8sPodRunner implements cni.PodRunner against a real cluster.
type k8sPodRunner struct {
	cs kubernetes.Interface
}

func (r *k8sPodRunner) Create(ctx context.Context, ns string, pod *corev1.Pod) (*corev1.Pod, error) {
	return r.cs.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
}

func (r *k8sPodRunner) Delete(ctx context.Context, ns, name string) error {
	err := r.cs.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}

func (r *k8sPodRunner) Get(ctx context.Context, ns, name string) (*corev1.Pod, error) {
	return r.cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
}

// WaitRunning polls until the pod is Running+Ready or timeout.
func (r *k8sPodRunner) WaitRunning(ctx context.Context, ns, name string, timeout time.Duration) (*corev1.Pod, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		p, err := r.cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil && p.Status.Phase == corev1.PodRunning {
			return p, nil
		}
		// check for a terminal failure
		if err == nil {
			for _, cs := range p.Status.ContainerStatuses {
				if cs.State.Terminated != nil {
					return p, fmt.Errorf("pod %s container terminated", name)
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("pod %s/%s did not become Running within %s", ns, name, timeout)
}

// findNodeDebugPod returns a privileged pod (often a CNI daemonset pod or a node
// debug pod) on the given node that we can exec drift probes into. Best-effort.
func findNodeDebugPod(ctx context.Context, cs kubernetes.Interface, node string) (ns, name string, ok bool) {
	pods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", node).String(),
	})
	if err != nil {
		return "", "", false
	}
	// Prefer kube-proxy, then any hostNetwork pod, then any running pod.
	pref := func(p corev1.Pod) int {
		score := 0
		if strings.Contains(strings.ToLower(p.Name), "kube-proxy") {
			score = 100
		}
		if p.Spec.HostNetwork {
			score += 50
		}
		for _, c := range p.Spec.Containers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				score += 30
			}
		}
		return score
	}
	best := -1
	var bestPod *corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		s := pref(*p)
		if s > best {
			best = s
			bestPod = p
		}
	}
	if bestPod == nil {
		return "", "", false
	}
	return bestPod.Namespace, bestPod.Name, true
}

// cniExecClient adapts kube.RemoteExecutor to the cni.ExecClient interface.
type cniExecClient struct{ inner cniExecer }

type cniExecer interface {
	Run(ctx context.Context, namespace, pod string, cmd []string, timeout time.Duration) (string, string, int, error)
}

func (c *cniExecClient) Run(ctx context.Context, namespace, pod string, cmd []string, timeout time.Duration) (string, string, int, error) {
	return c.inner.Run(ctx, namespace, pod, cmd, timeout)
}

// newCNIExecClient builds a cni.ExecClient backed by RemoteExecutor.
func newCNIExecClient(f *kube.Factory) cni.ExecClient {
	return &cniExecClient{inner: kube.NewRemoteExecutor(f)}
}
