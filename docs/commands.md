# knm-cli command design notes

This document captures the design intent, current implementation depth, and
roadmap for each command group. The shared contract: **every command runs,
produces real output, and never silently no-ops** — shallow areas are marked
with `ℹ not yet implemented:` notes in the output.

---

## 1. `knm trace SRC DST` — network path tracer

**Pain point:** debugging "Pod A can't reach Pod B" requires manually chaining
CNI → iptables → DNS → NetworkPolicy → Endpoints → routing.

**Current depth (✅ API walk + ✅ active probing):** walks the chain a real
packet traverses, marks the first broken hop, and now also **actively probes**
inside the source Pod. See [`docs/trace.md`](trace.md) for the full design.

Hop chain:
1. Source Pod (IP, node, ready state)
2. DNS — service present **+ actively resolves** the target name via `getent`/`nslookup`
3. **NetworkPolicy** — static src→dst allow/deny verdict (reuses the policy engine)
4. Service (exists? type, ClusterIP, port inference)
5. Endpoints (ready backing pods; flags 0-ready as FAIL with terminating count)
6. **TCP Connect** — active handshake to a backend `:port` via `nc`/`bash /dev/tcp`/`python3`/`wget`/`curl`
7. kube-proxy (mode detection from the kube-proxy DaemonSet)
8. CNI (best-effort detection; same-node vs cross-node)
9. Target Pod (IP, running, ready)

**Probe modes:** `--probe auto` (default) | `api` (read-only, no exec) | `tcp` | `dns`;
`--no-exec` shortcut; `--tcpconnect-timeout`. Output adds `-o dot`/`-o mermaid`
path graphs. Active hops degrade to SKIP/WARN (never crash) when exec is
unavailable — no `pods/exec` RBAC, a stripped image, or `--probe=api`.

**Done:** ✅ API walk · ✅ DNS resolve · ✅ NetworkPolicy verdict · ✅ TCP connect · ✅ path graphs

**Roadmap (next-round trace deepening):** iptables/ipvs rule inspection via
node exec, CNI datapath probe, path-MTU/df-ping discovery, ephemeral debug
container injection (for images with zero probe tools).

---

## 2. `knm policy` — NetworkPolicy reasoning

**Pain point:** "who can talk to whom" is opaque; policies are CNI-specific.

### `check POD` (✅)
Lists every NetworkPolicy selecting a Pod and reports ingress/egress isolation.

### `simulate` (✅ — pure logic, no cluster)
Static allow/deny verdict from YAML only. Implements the NetworkPolicy v1
semantics honored by all CNIs: default-allow unless a selecting policy with an
Ingress section isolates the Pod; ipBlock (with `except`), podSelector and
namespaceSelector peers; protocol/port matching. CI-friendly (no kubeconfig).

### `matrix` (✅)
Pod×Pod ingress allow matrix for a namespace (✓/✗ grid), via the same engine.

### `generate` (🟡)
Emits a default-deny-all baseline. With `--from-flows`, ingests an observed-
flow dump and synthesizes least-privilege egress rules grouped by source ns.
Live eBPF flow capture is the roadmap item (`docs/ebpf.md`).

---

## 3. `knm observe` — eBPF real-time observation (🟡)

**Pain point:** Cilium Hubble is heavy and Cilium-bound.

`flows` / `events` probe `ebpf.Availability()` and degrade to an API-level
service map when the backend is unavailable. See `docs/ebpf.md`.

---

## 4. `knm gateway` — Gateway API lifecycle

**Pain point:** Gateway API is GA but the Ingress-era tooling maturity is missing.

### `migrate` (✅)
Converts Ingress → Gateway + HTTPRoute. Groups by (namespace, class) into one
Gateway; one HTTPRoute per (namespace, host) aggregating paths; maps nginx
redirect/canary/rewrite annotations with explicit warnings for what couldn't be
auto-translated. Emits the generated YAML + a migration diff report.

### `lint` (✅)
Validates a Gateway API set (file or live cluster): duplicate listener ports,
hostname conflicts, TLS listeners missing certificateRefs, dangling parentRefs,
unknown backend Service refs, cross-namespace backend refs needing a
ReferenceGrant, empty rules.

### `replay` (🔲)
Traffic recorder + diff engine: record prod, replay in staging, compare status
code / latency / headers. Methodology only in this release.

---

## 5. `knm cni` — CNI testing & comparison

### `bench` (✅ method)
Detects the installed CNI and prints a standardized benchmark methodology
(pod-to-pod latency, cross-node throughput, NetworkPolicy apply time, pod
creation readiness). Automated runner is roadmap.

### `fault` (✅ catalog)
Catalog of CNI fault-injection scenarios (veth severed, IP pool exhaustion, BGP
down, MTU mismatch, kube-proxy flush) with the injection command for each.

### `drift` (✅ baseline)
Collects node podCIDR + pod count as a baseline. Continuous expected-vs-actual
diff (iptables/route/veth counts) with drift alerts is roadmap.

---

## 6. `knm security` — network security

### `baseline` (🟡)
Per-Pod metadata table; eBPF learning + deviation alerts are roadmap.

### `dns` (🟡)
Locates CoreDNS pods; metrics scraping (prometheus plugin) + DNS tunnel/entropy
anomaly detection is roadmap.

---

## 7. `knm mc` — multi-cluster & hybrid-cloud

### `topo` (✅)
Reads all kubeconfig contexts and builds a cross-cluster service topology
(context/cluster/namespace/service counts).

### `policy-sync` (✅)
Dry-run diffs a named NetworkPolicy across all contexts against the current
context's copy.

### `connectivity` (✅ baseline)
Collects node IPs/regions/podCIDRs as a connectivity baseline. Active MTU probe
(df-ping), route symmetry check, and on-prem↔cloud VPC reachability is roadmap.

---

## 8. `knm gpu` — AI/GPU workload networking

### `rdma` (✅ detect)
Detects GPU nodes (`nvidia.com/gpu` capacity), Multus annotations, SR-IOV
device-plugin resources, and RDMA interface hints.

### `analyze` (🟡)
eBPF on RDMA/RoCE NICs + NCCL-test parsing to rank slow AllReduce links.
Roadmap.

### `qos` (🔲)
QoS manager that prioritizes RDMA traffic over HTTP/inference via DCN/ECN +
an admission webhook. Status table only.

---

## 9. `knm sandbox` & `knm depgraph` — developer experience

### `sandbox` (✅ detect)
Detects kind/k3d in PATH; one-click multi-CNI cluster bring-up + interactive
tutorial is roadmap.

### `depgraph` (✅)
Derives a dependency graph (Service → backing Pods via EndpointSlice
readiness; NetworkPolicy → Service when it selects exposed pods) and renders
mermaid/dot/table.
