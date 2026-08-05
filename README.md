# knm — Kubernetes Network Master CLI

`knm` is a single binary for **debugging, observing, securing, and migrating**
Kubernetes networking. It is also installable as the kubectl plugin
`kubectl-net`, so `kubectl net <subcommand>` works.

> Kubernetes networking is the classic "black box": to debug one broken
> Service you juggle CNI state, iptables/IPVS, DNS, NetworkPolicy, Endpoints,
> and node routes by hand. `knm` glues those layers together in one tool.

This is an **early release**: every command is wired up and produces real,
useful output, but the deep features (active probing, eBPF capture, traffic
replay) are explicitly marked as roadmap items. See each command's
`ℹ not yet implemented:` note and [`docs/`](docs/).

---

## Install

### From source

```bash
git clone https://github.com/kudig-io/kubernetes-network-master
cd kubernetes-network-master
make build          # → ./bin/knm

# install to $GOPATH/bin AND create the kubectl-net plugin alias:
make install
```

### Use as a kubectl plugin

`make install` places two binaries on your `PATH`:

```bash
knm trace pod/web svc/api                 # standalone
kubectl net trace pod/web svc/api         # same binary, plugin form
```

Both share one codebase; the binary detects when it's invoked as
`kubectl-net` and strips kubectl's `net` argument automatically.

### Verify

```bash
knm version
knm --help
```

---

## Command reference

All commands accept the standard kubectl flags (`--kubeconfig`, `--context`,
`-n`, `-A`, `--as`, …) and a unified `-o table|wide|json|yaml|dot|mermaid`.

| Command | Category | What it does | Status |
|---|---|---|---|
| `knm trace SRC DST` | Debug/Observability | Walk DNS→NetworkPolicy→Service→Endpoints→TCP→CNI→Pod, mark the break | ✅ + active probe |
| `knm policy check POD` | Debug/Security | List policies selecting a Pod + isolation state | ✅ |
| `knm policy simulate` | Security | Pure-static allow/deny verdict (no cluster needed) | ✅ |
| `knm policy matrix` | Security | Pod×Pod ingress allow matrix | ✅ |
| `knm policy generate` | Security | default-deny baseline / least-privilege from flows | 🟡 eBPF→fallback |
| `knm observe flows` / `events` | Observability | eBPF live flows/events (CNI-agnostic) | 🟡 eBPF→fallback |
| `knm gateway migrate` | Gateway API | Ingress → Gateway + HTTPRoute + diff report | ✅ |
| `knm gateway lint` | Gateway API | Catch route conflicts, dangling refs, missing TLS | ✅ |
| `knm gateway replay` | Gateway API | Replay recorded traffic against a new config | 🔲 roadmap |
| `knm cni bench` | CNI | Detect CNI + standardized benchmark method | ✅ method |
| `knm cni fault` | CNI | List chaos fault-injection scenarios | ✅ catalog |
| `knm cni drift` | CNI | Expected-vs-actual node network state baseline | ✅ baseline |
| `knm security baseline` | Security | Per-Pod behavior baseline + deviation alerts | 🟡 eBPF→fallback |
| `knm security dns` | Security | CoreDNS stats / DNS anomaly first-pass | 🟡 |
| `knm mc topo` | Multi-cluster | Cross-context service topology | ✅ |
| `knm mc policy-sync` | Multi-cluster | Dry-run diff a NetworkPolicy across contexts | ✅ |
| `knm mc connectivity` | Multi-cluster | Hybrid-cloud MTU/route/connectivity self-check | ✅ baseline |
| `knm gpu rdma` | AI/GPU | GPU nodes, Multus/SR-IOV, RDMA readiness | ✅ detect |
| `knm gpu analyze` | AI/GPU | Locate slow NCCL/AllReduce links | 🟡 eBPF→fallback |
| `knm gpu qos` | AI/GPU | RDMA-vs-HTTP priority + QoS manager | 🔲 roadmap |
| `knm sandbox` | DevEx | kind/k3d multi-CNI sandbox + tutorial | ✅ detect |
| `knm depgraph` | DevEx | Service+EndpointSlice+NetworkPolicy → mermaid/dot | ✅ |
| `knm version` / `completion` | — | Build info / shell completion | ✅ |

Legend: ✅ implemented (shallow) · 🟡 implemented with eBPF degrade path · 🔲 roadmap

---

## Examples

### Trace a broken connection

```bash
$ knm trace pod/debug svc/api
trace pod/debug → svc/api
+----------------+--------+----------------------------------------------------------+
| STAGE          | STATUS | DETAIL                                                   |
+----------------+--------+----------------------------------------------------------+
| Source Pod     | OK     | default/debug ip=10.244.1.5 node=node-1                  |
| DNS            | OK     | kube-dns clusterIP=10.96.0.10 — resolved "api.default…"  |
|                |        |   → 10.96.7.7                                            |
| NetworkPolicy  | OK     | no NetworkPolicies in default → default allow            |
| Service        | OK     | default/api type=ClusterIP clusterIP=10.96.7.7           |
| Endpoints      | FAIL   | 0 ready backing pods — Service has no usable Endpoints   |
| ...            |        |                                                          |
+----------------+--------+----------------------------------------------------------+
✗ path is broken at the first FAIL hop above
ℹ kube-proxy rule inspection, CNI datapath probe, path-MTU discovery are roadmap items
```

Active probes (DNS resolve, TCP connect) run inside the source Pod and auto-
detect available tools (`getent`/`nslookup`; `nc`/`bash /dev/tcp`/`wget`/`curl`).
They degrade to SKIP/WARN — never crash — under `--probe=api` or without
`pods/exec` RBAC. Render the chain as a path graph with `-o mermaid`/`-o dot`.
See [`docs/trace.md`](docs/trace.md).

### Simulate a NetworkPolicy (CI-friendly, no cluster)

```bash
$ knm policy simulate --policy netpol.yaml --src pod/app --dst pod/db --port 5432
+---------+------------------+-------------------------------------------------------+
| ALLOWED | INGRESS-ISOLATED | REASON                                                |
+---------+------------------+-------------------------------------------------------+
| yes     | yes              | allowed by default/db-allow-from-app via ingress peer |
+---------+------------------+-------------------------------------------------------+
```

Endpoints auto-seed `app=<name>`/`pod=<name>` labels; override with
`--src-labels app=web,team=payments --dst-labels app=db`.

### Migrate Ingress → Gateway API

```bash
$ knm gateway migrate -f ingress.yaml
# prints the generated Gateway + HTTPRoute YAML, then a migration diff table.
```

### Render a service dependency graph

```bash
knm depgraph -o mermaid        # paste into any mermaid renderer
knm depgraph -A -o dot | dot -Tsvg > deps.svg
```

---

## Output formats

Every command honors `-o`:

- `table` (default) — human-friendly
- `wide` — extra detail columns
- `json` / `yaml` — structured, CI-friendly
- `dot` / `mermaid` — for graph-producing commands (`depgraph`, `mc topo`)

---

## eBPF features & graceful degrade

Several commands (`observe`, `security baseline`, `policy generate`,
`gpu analyze`) ultimately want eBPF for zero-instrument kernel visibility.
This build does not yet ship the libbpf backend, and on non-Linux hosts it
can't. Rather than crash, those commands:

1. probe `ebpf.Availability()`,
2. print a clear reason (`eBPF requires a Linux kernel; current OS is darwin`),
3. fall back to an API-level implementation (e.g. a static service map).

See [`docs/ebpf.md`](docs/ebpf.md) for the roadmap to a real
`libbpf-go` / Aya backend behind the same degrade contract.

---

## Project layout

```
cmd/knm/              # entry point (kubectl-net alias detection)
internal/
  cli/                # cobra command tree (thin layer over logic)
  kube/               # kubectl-style flag factory + clientset cache
  ebpf/               # availability probe + degrade messaging
  output/             # table/json/yaml/dot/mermaid renderer
  version/            # build-time metadata
  trace/ policy/ gateway/ cni/ observe/ security/ mc/ gpu/ sandbox/ depgraph/
                      # pure domain logic (unit-tested, cluster-free where possible)
docs/                 # per-feature design notes
```

## Development

```bash
make test       # unit tests
make vet        # go vet
make lint       # vet + gofmt check
make run ARGS="policy simulate --policy x.yaml ..."
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
