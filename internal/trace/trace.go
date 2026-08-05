package trace

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/kudig-io/knm-cli/internal/policy"
)

// Client is the subset of kubernetes.Interface the tracer needs. We alias to
// the real interface so the concrete clientset AND fake.NewSimpleClientset both
// satisfy it directly (exec is handled separately via ExecClient).
type Client = kubernetes.Interface

// RefKind identifies what a trace endpoint refers to.
type RefKind int

const (
	RefPod RefKind = iota
	RefService
)

// Ref is a resolved source or destination reference.
type Ref struct {
	Kind      RefKind
	Namespace string
	Name      string
}

// Options controls one trace run.
type Options struct {
	Probe            ProbeMode
	TCPConnectWait   time.Duration
	Port             int32  // target port; 0 = infer from Service
	DefaultNamespace string // -n value used by ParseRef for bare names

	// L1 deepening switches (default off; need exec / RBAC).
	InspectRules   bool              // exec kube-proxy pod to check ClusterIP rules
	MTUProbe       bool              // df-ping path-MTU discovery from source pod
	DebugContainer bool              // inject an ephemeral debug container when source lacks tools
	Injector       EphemeralInjector // optional; if nil and DebugContainer set, hop degrades
}

// Result is the full hop chain plus the resolved objects (useful for graphing).
type Result struct {
	Hops     []Hop
	SrcPod   *corev1.Pod
	DstPod   *corev1.Pod
	Service  *corev1.Service
	Backends []*corev1.Pod // ready backing pods behind a Service
}

// Run executes the trace and returns the hop chain. It never panics; missing
// resources produce FAIL hops and missing exec produce SKIP/WARN hops.
func Run(ctx context.Context, cs Client, exec ExecClient, src, dst Ref, opts Options) Result {
	if exec == nil {
		exec = NoExec
	}
	if opts.TCPConnectWait == 0 {
		opts.TCPConnectWait = 2 * time.Second
	}
	r := Result{}

	// 1. Source Pod.
	srcPod, err := cs.CoreV1().Pods(src.Namespace).Get(ctx, src.Name, metav1.GetOptions{})
	if err != nil {
		r.Hops = append(r.Hops, Fail("Source Pod", fmt.Sprintf("get pod %s/%s: %v", src.Namespace, src.Name, err)))
		return r
	}
	r.SrcPod = srcPod
	r.Hops = append(r.Hops, Hop{
		Stage: "Source Pod", Status: podStatus(srcPod),
		Detail: fmt.Sprintf("%s/%s ip=%s node=%s", srcPod.Namespace, srcPod.Name, podIP(srcPod), nodeName(srcPod)),
	})

	// Resolve the Service object up front; several hops need it (DNS resolve,
	// NetworkPolicy context, port inference).
	var svc *corev1.Service
	if dst.Kind == RefService {
		s, err := cs.CoreV1().Services(dst.Namespace).Get(ctx, dst.Name, metav1.GetOptions{})
		if err != nil {
			r.Hops = append(r.Hops, Fail("Service", fmt.Sprintf("get svc %s/%s: %v", dst.Namespace, dst.Name, err)))
			return r
		}
		svc = s
		r.Service = svc
		if opts.Port == 0 && len(svc.Spec.Ports) > 0 {
			opts.Port = int32(svc.Spec.Ports[0].Port)
		}
	}

	// 2. DNS — service present + active resolution from the source Pod.
	r.Hops = append(r.Hops, dnsHop(ctx, cs, exec, srcPod, svc, dst, opts))

	// 3. NetworkPolicy — static src→dst verdict (no exec needed).
	// Resolve the destination's representative labels first: prefer a ready
	// backend pod's labels (most accurate), else the Service selector, so the
	// policy engine evaluates the real pod the packet would hit.
	dstLabels := resolveDstLabels(ctx, cs, svc, dst)
	r.Hops = append(r.Hops, policyHop(ctx, cs, srcPod, dst, dstLabels))

	// 4. Service hop (or direct target pod).
	var backends []*corev1.Pod
	if dst.Kind == RefService {
		r.Hops = append(r.Hops, Hop{
			Stage: "Service", Status: StatusOK,
			Detail: fmt.Sprintf("%s/%s type=%s clusterIP=%s", svc.Namespace, svc.Name, svc.Spec.Type, svc.Spec.ClusterIP),
		})
		// 5. Endpoints.
		epHop, pods := endpointsHop(ctx, cs, svc)
		r.Hops = append(r.Hops, epHop)
		backends = pods
		r.Backends = pods
		if len(pods) == 0 {
			return r
		}
		r.DstPod = pods[0]
	} else {
		dp, err := cs.CoreV1().Pods(dst.Namespace).Get(ctx, dst.Name, metav1.GetOptions{})
		if err != nil {
			r.Hops = append(r.Hops, Fail("Target Pod", fmt.Sprintf("get pod %s/%s: %v", dst.Namespace, dst.Name, err)))
			return r
		}
		r.DstPod = dp
		backends = []*corev1.Pod{dp}
		r.Hops = append(r.Hops, Hop{
			Stage: "Target Pod (direct)", Status: podStatus(dp),
			Detail: fmt.Sprintf("%s/%s ip=%s", dp.Namespace, dp.Name, podIP(dp)),
		})
	}

	// 6. TCP Connect — active handshake to each backend :port from source Pod.
	if opts.Port > 0 {
		r.Hops = append(r.Hops, tcpConnectHop(ctx, exec, srcPod, backends, opts))
	}

	// 6b. Debug Container — inject an ephemeral container if requested and the
	// source pod lacks probe tools. This is a side-channel, not on the data path.
	if opts.DebugContainer {
		r.Hops = append(r.Hops, debugContainerHop(ctx, cs, opts.Injector, srcPod))
	}

	// 7. kube-proxy mode + (optional) active rule inspection for the ClusterIP.
	r.Hops = append(r.Hops, proxyHop(ctx, cs))
	if opts.InspectRules && svc != nil && svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
		r.Hops = append(r.Hops, rulesHop(ctx, cs, exec, srcPod, svc.Spec.ClusterIP))
	}

	// 7b. Path-MTU — df-ping the first backend from the source Pod.
	if opts.MTUProbe && r.DstPod != nil && len(podIP(r.DstPod)) > 0 && podIP(r.DstPod) != "?" {
		r.Hops = append(r.Hops, pathMtuHop(ctx, exec, srcPod, podIP(r.DstPod), opts))
	}

	// 8. CNI.
	r.Hops = append(r.Hops, cniHop(ctx, cs, srcPod, r.DstPod))

	// 9. Final target pod summary (Service path).
	if dst.Kind == RefService && r.DstPod != nil {
		r.Hops = append(r.Hops, Hop{
			Stage: "Target Pod", Status: podStatus(r.DstPod),
			Detail: fmt.Sprintf("%s/%s ip=%s node=%s", r.DstPod.Namespace, r.DstPod.Name, podIP(r.DstPod), nodeName(r.DstPod)),
		})
	}
	return r
}

// Fail is a convenience constructor for a FAIL hop that marks the break point.
func Fail(stage, msg string) Hop {
	return Hop{Stage: stage, Status: StatusFail, Detail: msg, Note: "break here"}
}

// --- hop helpers ---

func podStatus(p *corev1.Pod) Status {
	if p == nil {
		return StatusWarn
	}
	if p.Status.Phase != corev1.PodRunning {
		return StatusWarn
	}
	for _, cs := range p.Status.ContainerStatuses {
		if !cs.Ready {
			return StatusWarn
		}
	}
	return StatusOK
}

func podIP(p *corev1.Pod) string {
	if p == nil {
		return "?"
	}
	if len(p.Status.PodIP) > 0 {
		return p.Status.PodIP
	}
	return "<unassigned>"
}

func nodeName(p *corev1.Pod) string {
	if p == nil {
		return "?"
	}
	return p.Spec.NodeName
}

// dnsHop checks the cluster DNS service exists and, when exec is available,
// actively resolves the target Service FQDN from inside the source Pod.
func dnsHop(ctx context.Context, cs Client, exec ExecClient, srcPod *corev1.Pod, svc *corev1.Service, dst Ref, opts Options) Hop {
	// Static: DNS service present?
	base := Hop{Stage: "DNS"}
	svcs, err := cs.CoreV1().Services("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		base.Status = StatusSkip
		base.Detail = "could not list kube-system services: " + err.Error()
		return base
	}
	dnsClusterIP := ""
	found := false
	for _, s := range svcs.Items {
		if strings.Contains(strings.ToLower(s.Name), "dns") {
			found = true
			dnsClusterIP = s.Spec.ClusterIP
			break
		}
	}
	if !found {
		base.Status = StatusWarn
		base.Detail = "no DNS service found in kube-system"
		return base
	}
	base.Detail = fmt.Sprintf("kube-dns clusterIP=%s", dnsClusterIP)

	// Active resolve: only meaningful for a Service destination.
	if svc == nil || opts.Probe == ProbeAPI {
		base.Status = StatusOK
		if opts.Probe == ProbeAPI {
			base.Note = "active resolve skipped (--probe=api)"
		}
		return base
	}
	fqdn := svc.Name + "." + svc.Namespace + ".svc"
	out, _, code, runErr := exec.Run(ctx, srcPod.Namespace, srcPod.Name,
		dnsResolveCmd(fqdn), 3*time.Second)
	if IsNoExec(runErr) {
		base.Status = StatusOK
		base.Note = "active resolve skipped (--no-exec)"
		return base
	}
	if runErr != nil || code != 0 {
		base.Status = StatusFail
		base.Detail += fmt.Sprintf(" — resolve %q FAILED (exit %d)", fqdn, code)
		if strings.TrimSpace(out) != "" {
			base.Note = out
		}
		return base
	}
	ips := parseResolveOutput(out)
	if len(ips) == 0 {
		base.Status = StatusWarn
		base.Detail += fmt.Sprintf(" — resolved %q but no IPs parsed", fqdn)
		base.Note = truncate(out, 80)
		return base
	}
	base.Status = StatusOK
	base.Detail += fmt.Sprintf(" — resolved %q → %s", fqdn, strings.Join(ips, ", "))
	return base
}

// resolveDstLabels determines the label set that best represents the destination
// pod for NetworkPolicy evaluation: a ready backend pod's labels if any, else
// the Service selector. Returns an empty set if nothing is resolvable.
func resolveDstLabels(ctx context.Context, cs Client, svc *corev1.Service, dst Ref) labels.Set {
	if svc != nil {
		// Try ready backend pods first.
		_, pods := endpointsHop(ctx, cs, svc)
		if len(pods) > 0 {
			return labels.Set(pods[0].Labels)
		}
		if len(svc.Spec.Selector) > 0 {
			return svc.Spec.Selector
		}
	}
	if dst.Kind == RefPod {
		if p, err := cs.CoreV1().Pods(dst.Namespace).Get(ctx, dst.Name, metav1.GetOptions{}); err == nil {
			return labels.Set(p.Labels)
		}
	}
	return labels.Set{}
}

// policyHop renders a static src→dst NetworkPolicy verdict using the policy
// engine. No exec is needed, so it always runs.
func policyHop(ctx context.Context, cs Client, srcPod *corev1.Pod, dst Ref, dstLabels labels.Set) Hop {
	hop := Hop{Stage: "NetworkPolicy"}
	if srcPod == nil {
		hop.Status = StatusSkip
		hop.Detail = "source pod unknown"
		return hop
	}
	ns := dst.Namespace
	pols, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		hop.Status = StatusSkip
		hop.Detail = "could not list NetworkPolicies: " + err.Error()
		return hop
	}
	if len(pols.Items) == 0 {
		hop.Status = StatusOK
		hop.Detail = fmt.Sprintf("no NetworkPolicies in %s → default allow", ns)
		return hop
	}

	dstEp := policy.Endpoint{Namespace: dst.Namespace, Labels: dstLabels}
	srcEp := policy.Endpoint{Namespace: srcPod.Namespace, Labels: labels.Set(srcPod.Labels)}

	eng := policy.NewEngine(pols.Items)
	res := eng.Simulate(policy.Query{Dest: dstEp, Src: srcEp})
	hop.Detail = res.Reason
	if res.Allowed {
		hop.Status = StatusOK
	} else {
		hop.Status = StatusFail
		hop.Note = "NetworkPolicy denies this src→dst"
	}
	return hop
}

// endpointsHop resolves a Service to its ready backing pods.
func endpointsHop(ctx context.Context, cs Client, svc *corev1.Service) (Hop, []*corev1.Pod) {
	epsList, err := cs.DiscoveryV1().EndpointSlices(svc.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "kubernetes.io/service-name=" + svc.Name,
	})
	if err == nil && len(epsList.Items) > 0 {
		var ready, terminating int
		var pods []*corev1.Pod
		for _, eps := range epsList.Items {
			for _, ep := range eps.Endpoints {
				if ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
					terminating++
					continue
				}
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				ready++
				if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
					if p, err := cs.CoreV1().Pods(ep.TargetRef.Namespace).Get(ctx, ep.TargetRef.Name, metav1.GetOptions{}); err == nil {
						pods = append(pods, p)
					}
				}
			}
		}
		status := StatusOK
		detail := fmt.Sprintf("%d ready backing pods", ready)
		if ready == 0 {
			status = StatusFail
			detail = "0 ready backing pods — Service has no usable Endpoints"
			if terminating > 0 {
				detail += fmt.Sprintf(" (%d terminating)", terminating)
			}
		}
		return Hop{Stage: "Endpoints", Status: status, Detail: detail}, pods
	}
	return Hop{Stage: "Endpoints", Status: StatusFail, Detail: "no EndpointSlices for Service"}, nil
}

// tcpConnectHop performs an active TCP connect from the source Pod to each
// ready backend on the target port. This is the strongest "is the app actually
// reachable?" signal short of an HTTP request.
func tcpConnectHop(ctx context.Context, exec ExecClient, srcPod *corev1.Pod, backends []*corev1.Pod, opts Options) Hop {
	hop := Hop{Stage: "TCP Connect"}
	if opts.Probe == ProbeAPI {
		hop.Status = StatusSkip
		hop.Note = "TCP probe skipped (--probe=api)"
		hop.Detail = fmt.Sprintf("would probe %d backend(s) on :%d", len(backends), opts.Port)
		return hop
	}
	// Build a probe that tries nc / bash /dev/tcp / wget in priority order,
	// targeting the first backend IP:port (probe one to keep it cheap; note
	// the others).
	if len(backends) == 0 {
		hop.Status = StatusSkip
		hop.Detail = "no backends to probe"
		return hop
	}
	ip := podIP(backends[0])
	addr := fmt.Sprintf("%s:%d", ip, opts.Port)
	cmd := tcpConnectCmd(addr, opts.TCPConnectWait)
	out, _, code, runErr := exec.Run(ctx, srcPod.Namespace, srcPod.Name, cmd, opts.TCPConnectWait+time.Second)
	if IsNoExec(runErr) {
		hop.Status = StatusSkip
		hop.Detail = fmt.Sprintf("would connect to %s (skipped: --no-exec)", addr)
		return hop
	}
	if runErr != nil {
		hop.Status = StatusWarn
		hop.Detail = fmt.Sprintf("exec error probing %s: %v", addr, runErr)
		return hop
	}
	if code == 0 {
		hop.Status = StatusOK
		hop.Detail = fmt.Sprintf("connected to %s", addr)
		if len(backends) > 1 {
			hop.Note = fmt.Sprintf("(+%d more backends not probed)", len(backends)-1)
		}
		return hop
	}
	// Non-zero exit: port closed / blocked. nc returns 1 on connect failure.
	hop.Status = StatusFail
	hop.Detail = fmt.Sprintf("cannot connect to %s (exit %d)", addr, code)
	hop.Note = "port not listening or blocked by policy/firewall"
	if t := strings.TrimSpace(out); t != "" {
		hop.Note = truncate(t, 120)
	}
	return hop
}

func proxyHop(ctx context.Context, cs Client) Hop {
	ds, err := cs.AppsV1().DaemonSets("kube-system").Get(ctx, "kube-proxy", metav1.GetOptions{})
	if err != nil {
		return Hop{Stage: "kube-proxy", Status: StatusSkip, Detail: "kube-proxy DaemonSet not found or unreadable"}
	}
	mode := "iptables (default)"
	for _, c := range ds.Spec.Template.Spec.Containers {
		for _, a := range c.Args {
			if strings.Contains(a, "proxy-mode=") {
				mode = strings.Split(a, "=")[1]
			}
		}
	}
	return Hop{Stage: "kube-proxy", Status: StatusOK, Detail: fmt.Sprintf("mode=%s", mode)}
}

func cniHop(ctx context.Context, cs Client, src, dst *corev1.Pod) Hop {
	cni := DetectCNI(ctx, cs)
	if src == nil || dst == nil {
		return Hop{Stage: "CNI", Status: StatusSkip, Detail: "missing src/dst pod"}
	}
	footnote := "cross-node"
	if src.Spec.NodeName == dst.Spec.NodeName && src.Spec.NodeName != "" {
		footnote = "same-node"
	}
	return Hop{
		Stage: "CNI", Status: StatusOK,
		Detail: fmt.Sprintf("cni=%s %s (src=%s dst=%s); datapath probe TODO", cni, footnote, src.Status.PodIP, dst.Status.PodIP),
	}
}

// DetectCNI makes a best-effort guess at the installed CNI from well-known
// system pods. Exported because the `cni` command group also uses it.
func DetectCNI(ctx context.Context, cs Client) string {
	candidates := []struct {
		ns, match, name string
	}{
		{"kube-system", "calico", "calico"},
		{"kube-system", "cilium", "cilium"},
		{"kube-system", "flannel", "flannel"},
		{"kube-system", "weave", "weave"},
		{"kube-system", "antrea", "antrea"},
		{"kube-system", "multus", "multus"},
	}
	for _, c := range candidates {
		pods, err := cs.CoreV1().Pods(c.ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, p := range pods.Items {
			ln := strings.ToLower(p.Name)
			if strings.Contains(ln, c.match) {
				return c.name
			}
		}
	}
	return "unknown"
}

// kubeProxyPodForNode finds a kube-proxy DaemonSet pod running on the given
// node, so we can exec into it for rule inspection. Returns nil if none.
func kubeProxyPodForNode(ctx context.Context, cs Client, node string) *corev1.Pod {
	if node == "" {
		return nil
	}
	pods, err := cs.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
	})
	if err != nil {
		return nil
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		// The fake clientset ignores field selectors, so double-check the node.
		if p.Spec.NodeName != node {
			continue
		}
		// Match common kube-proxy naming / labels.
		if strings.Contains(strings.ToLower(p.Name), "kube-proxy") {
			return p
		}
		for _, c := range p.Spec.Containers {
			if strings.Contains(strings.ToLower(c.Name), "kube-proxy") {
				return p
			}
		}
	}
	return nil
}

// rulesHop execs the kube-proxy pod on the source node to check whether the
// Service ClusterIP has a matching data-plane rule (ipvs/iptables/nft). This is
// the strongest signal that kube-proxy has programmed the node for the Service.
func rulesHop(ctx context.Context, cs Client, exec ExecClient, srcPod *corev1.Pod, clusterIP string) Hop {
	hop := Hop{Stage: "kube-proxy rules"}
	if srcPod == nil || srcPod.Spec.NodeName == "" {
		hop.Status = StatusSkip
		hop.Detail = "source node unknown"
		return hop
	}
	kp := kubeProxyPodForNode(ctx, cs, srcPod.Spec.NodeName)
	if kp == nil {
		hop.Status = StatusWarn
		hop.Detail = fmt.Sprintf("no kube-proxy pod on node %s found", srcPod.Spec.NodeName)
		hop.Note = "rule inspection needs a kube-proxy pod on the source node"
		return hop
	}
	out, _, code, runErr := exec.Run(ctx, kp.Namespace, kp.Name, rulesCmd(clusterIP), 5*time.Second)
	if IsNoExec(runErr) {
		hop.Status = StatusSkip
		hop.Detail = fmt.Sprintf("would inspect rules for %s on %s (skipped: --no-exec)", clusterIP, kp.Name)
		return hop
	}
	if runErr != nil {
		hop.Status = StatusWarn
		hop.Detail = fmt.Sprintf("exec into kube-proxy %s failed: %v", kp.Name, runErr)
		hop.Note = "needs pods/exec on kube-system/kube-proxy"
		return hop
	}
	switch code {
	case 0:
		hop.Status = StatusOK
		hop.Detail = fmt.Sprintf("rule for %s present", clusterIP)
		hop.Note = truncate(strings.TrimSpace(out), 120)
	case 1:
		// explicit "no rule" from the probe
		hop.Status = StatusFail
		hop.Detail = fmt.Sprintf("no kube-proxy rule for %s — Service may not be programmed on this node yet", clusterIP)
		hop.Note = truncate(strings.TrimSpace(out), 120)
	case 3:
		hop.Status = StatusWarn
		hop.Detail = "neither ipvsadm, iptables, nor nft found in kube-proxy image"
		hop.Note = "kube-proxy image lacks rule-inspection tools"
	default:
		hop.Status = StatusWarn
		hop.Detail = fmt.Sprintf("rule inspection exited %d", code)
		hop.Note = truncate(strings.TrimSpace(out), 120)
	}
	return hop
}

// pathMtuHop runs a DF-ping path-MTU discovery from the source Pod to the
// destination IP. Reports the largest unfragmented payload and the implied
// path MTU. Useful for catching MTU-mismatch blackholes (a classic cross-node
// / overlay / VPN failure).
func pathMtuHop(ctx context.Context, exec ExecClient, srcPod *corev1.Pod, dstIP string, opts Options) Hop {
	hop := Hop{Stage: "Path-MTU"}
	if opts.Probe == ProbeAPI {
		hop.Status = StatusSkip
		hop.Note = "MTU probe skipped (--probe=api)"
		hop.Detail = fmt.Sprintf("would df-ping %s", dstIP)
		return hop
	}
	wait := opts.TCPConnectWait * 4
	if wait < 4*time.Second {
		wait = 4 * time.Second
	}
	out, _, code, runErr := exec.Run(ctx, srcPod.Namespace, srcPod.Name, mtuProbeCmd(dstIP), wait)
	if IsNoExec(runErr) {
		hop.Status = StatusSkip
		hop.Detail = fmt.Sprintf("would df-ping %s (skipped: --no-exec)", dstIP)
		return hop
	}
	if runErr != nil {
		hop.Status = StatusWarn
		hop.Detail = fmt.Sprintf("exec error probing MTU to %s: %v", dstIP, runErr)
		return hop
	}
	out = strings.TrimSpace(out)
	switch code {
	case 0:
		// stdout is the implied path MTU (payload + 28).
		if mtu, ok := atoiPositive(out); ok {
			hop.Status = StatusOK
			hop.Detail = fmt.Sprintf("path-MTU to %s = %d bytes", dstIP, mtu)
			if mtu < 1500 {
				hop.Note = fmt.Sprintf("below 1500 (payload %d)", mtu-28)
			}
		} else {
			hop.Status = StatusWarn
			hop.Detail = fmt.Sprintf("could not parse MTU output %q", out)
		}
	case 1:
		hop.Status = StatusWarn
		hop.Detail = fmt.Sprintf("no ping in source image; cannot probe MTU to %s", dstIP)
		hop.Note = "install iputils-ping or busybox in the source image"
	case 3:
		hop.Status = StatusFail
		hop.Detail = fmt.Sprintf("path-MTU to %s is below the smallest probed size", dstIP)
		hop.Note = "severe MTU mismatch or DF blackhole"
	default:
		hop.Status = StatusWarn
		hop.Detail = fmt.Sprintf("MTU probe exited %d", code)
		hop.Note = truncate(out, 120)
	}
	return hop
}

// debugContainerHop injects an ephemeral debug container (with a full network
// toolset) into the source Pod when the user opts in via --debug-container.
// This is the escape hatch for distroless / stripped images that lack
// nc/curl/ping. The hop reports whether injection succeeded; the actual
// re-probing happens on the subsequent Run because the ExecClient then targets
// the debug container. (In this build, injection is reported and the user is
// told to re-run; a future build can auto-retry.)
func debugContainerHop(ctx context.Context, cs Client, inj EphemeralInjector, srcPod *corev1.Pod) Hop {
	hop := Hop{Stage: "Debug Container"}
	if srcPod == nil {
		hop.Status = StatusSkip
		hop.Detail = "source pod unknown"
		return hop
	}
	if inj == nil {
		hop.Status = StatusSkip
		hop.Detail = "ephemeral injector not configured (needs --debug-container + cluster RBAC)"
		hop.Note = "set --debug-container and ensure ephemeralcontainers permission"
		return hop
	}
	name, err := inj.Inject(ctx, srcPod.Namespace, srcPod.Name, DebugContainerImage)
	if err != nil {
		hop.Status = StatusWarn
		hop.Detail = fmt.Sprintf("could not inject debug container: %v", err)
		hop.Note = "needs update ephemeralcontainers on pods (alpha subresource)"
		return hop
	}
	hop.Status = StatusOK
	hop.Detail = fmt.Sprintf("injected debug container %q into %s/%s", name, srcPod.Namespace, srcPod.Name)
	hop.Note = "re-run knm trace to probe via this container"
	return hop
}

// atoiPositive parses a non-negative integer; returns false on any error.
func atoiPositive(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
	}
	return n, true
}

// --- output/graph helpers used by the cli layer ---

// Broken reports whether any hop is a FAIL.
func (r Result) Broken() bool {
	for _, h := range r.Hops {
		if h.Status == StatusFail {
			return true
		}
	}
	return false
}

// truncate clips a string to n runes with an ellipsis.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

// parseResolveOutput pulls IP addresses out of getent/nc/wget DNS output. It is
// deliberately permissive: it scans whitespace-separated tokens for things that
// look like IPs.
func parseResolveOutput(out string) []string {
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		for _, tok := range strings.Fields(line) {
			if looksLikeIP(tok) {
				ips = append(ips, tok)
			}
		}
	}
	return ips
}

func looksLikeIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

// Reference for unused imports guard (keeps discoveryv1/netv1 documented).
var _ = discoveryv1.EndpointPort{}
var _ netv1.NetworkPolicy
