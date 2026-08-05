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

**Done:** ✅ API walk · ✅ DNS resolve · ✅ NetworkPolicy verdict · ✅ TCP connect
· ✅ iptables/ipvs/nft rule inspection (`--inspect-rules`) · ✅ path-MTU/df-ping
(`--mtu-probe`) · ✅ ephemeral debug container (`--debug-container`) · ✅ path graphs

**Roadmap:** CNI datapath probe (per-CNI veth/overlay health), route-symmetry
check, automated re-probe after debug-container injection.

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

## 3. `knm observe` — eBPF real-time observation (🟡 degrade paths now useful)

**Pain point:** Cilium Hubble is heavy and Cilium-bound.

- `flows` — eBPF path (roadmap) degrades to a real **API-level service map**
  (Services + ports from the cluster).
- `events` — eBPF path (roadmap: tcp_retransmit_skb / kfree_skb) degrades to
  **network-relevant Kubernetes Events** (filtered by reason + keyword:
  FailedScheduling/Unhealthy/NetworkUnavailable/"connection refused"/...).

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

### `replay` (✅)
Replays recorded traffic against a new Gateway URL and diffs responses. Parses
nginx/combined access logs (default) or HAR files (`--format har`); rewrites
each request's path+query onto `--target` (host swapped, headers preserved so
Host-based routing works); flags status-code diffs and latency regressions
above `--latency-band`. Pure Go HTTP, fully unit-tested.

---

## 5. `knm cni` — CNI testing & comparison

### `bench` (✅ live + 🟡 degrade)
Runs an actual iperf3 pod-to-pod benchmark: creates a server pod + client pod
(with anti-affinity so they land on different nodes), waits for Ready, runs
`iperf3 -J`, parses throughput + latency, then cleans up. Falls back to a
methodology guide if pod creation/image-pull/RBAC fails.

### `fault` (✅ runnable)
Catalog of CNI fault-injection scenarios (veth severed, IP pool exhaustion, BGP
down, MTU mismatch, kube-proxy flush) with **ready-to-run injection commands**.
With `-o yaml` emits chaos-mesh `NetworkChaos` manifests for the applicable
scenarios (loss/partition) — copy/paste to apply.

### `drift` (✅ snapshot)
Execs a privileged/debug pod on each node and snapshots iptables rule count,
route-table size, and interface count. Re-run after a change to spot drift
(rule-count growth, route leaks). The continuous diff/alert loop is roadmap.

---

## 6. `knm security` — network security

### `baseline` (✅ reachability + 🟡 eBPF roadmap)
Without eBPF: builds a per-Pod **reachability baseline** from EndpointSlices —
which Services expose each Pod. Pods with no exposing Service are flagged as the
first candidates to scrutinize for unsanctioned inbound. With eBPF (roadmap):
live connection learning + deviation alerts (exfil / lateral-move).

### `dns` (✅ scrape + 🟡 anomaly roadmap)
Scrapes CoreDNS Prometheus metrics at `:9153/metrics` and reports total queries,
error count (non-NOERROR rcodes), cache hit %, panics, and the top zone.
Degrades cleanly when the prometheus plugin/port is unavailable. DNS
tunnel/entropy anomaly detection is roadmap.

---

## 7. `knm mc` — multi-cluster & hybrid-cloud

### `topo` (✅)
Reads all kubeconfig contexts and builds a cross-cluster service topology
(context/cluster/namespace/service counts).

### `policy-sync` (✅)
Dry-run diffs a named NetworkPolicy across all contexts against the current
context's copy.

### `connectivity` (✅ baseline + ✅ active probe)
Collects node IPs/regions/podCIDRs. With `--active`, picks a representative pod
and df-pings each node's internal IP to measure path-MTU — catching
hybrid-cloud/VPN MTU mismatches. Route-symmetry and on-prem↔cloud VPC
reachability are roadmap.

---

## 8. `knm gpu` — AI/GPU workload networking

### `rdma` (✅ detect)
Detects GPU nodes (`nvidia.com/gpu` capacity), Multus annotations, SR-IOV
device-plugin resources, and RDMA interface hints.

### `analyze` (✅ file + 🟡 eBPF roadmap)
Parses an **nccl-test log file** (`-f`) and ranks operations by bandwidth to
surface the slowest link (the AllReduce bottleneck). The live eBPF path (RDMA
NIC stats correlated with NCCL rank) is roadmap.

### `qos` (✅ derived + 🔲 manager roadmap)
Reads each GPU node's annotations/capacity (Multus/SR-IOV/RoCE) and **derives
the actual QoS posture** — whether RDMA is prioritized (P1) vs best-effort
(P3), with the detected annotations. An enforcing DCN/ECN admission webhook is
roadmap.

---

## 9. `knm sandbox` & `knm depgraph` — developer experience

### `sandbox` (✅ lifecycle)
Detects kind/k3d in PATH; with `--create` brings up a named cluster
(`kind create cluster --name knm-sandbox` / `k3d cluster create`); `--delete`
tears it down. Multi-CNI swap + interactive tutorial is roadmap.

### `depgraph` (✅)
Derives a dependency graph (Service → backing Pods via EndpointSlice
readiness; NetworkPolicy → Service when it selects exposed pods) and renders
mermaid/dot/table.
