# `knm trace` — active network path probing

`knm trace SRC DST` walks the full network path a packet takes between two
workloads and marks the first broken hop. This document explains how the
**active probing** layer works, how it degrades, and how to validate it on a
local kind cluster.

---

## The hop chain

```
 1. Source Pod        Running, Ready, IP assigned
 2. DNS               cluster DNS present AND actively resolves the target name
 3. NetworkPolicy     static src→dst allow/deny verdict (policy engine)
 4. Service           exists, type, ClusterIP, port inference
 5. Endpoints         ready backing pods
 6. TCP Connect       active handshake from source Pod to backend :port
 6b. Debug Container  (opt-in) inject ephemeral netshoot container for stripped images
 7. kube-proxy        mode detection (iptables/ipvs/nft)
 7a. Rules            (opt-in) exec kube-proxy pod, check ClusterIP has a data-plane rule
 7b. Path-MTU         (opt-in) df-ping binary search from source Pod to target
 8. CNI               detected CNI, same-node vs cross-node
 9. Target Pod        IP, node, readiness
```

Each hop returns a status: **OK · WARN · FAIL · SKIP**. The first FAIL is
treated as the break point and printed under the table.

Hops 2 (DNS), 6 (TCP Connect), 7a (Rules), and 7b (Path-MTU) are **active
probes** — they run a command inside a Pod. Hop 3 (NetworkPolicy) is a static
verdict computed by the same engine behind `knm policy simulate`, so it needs
no exec and always runs. Hops 6b/7a/7b are opt-in (see flags below).

---

## Probe modes (`--probe`)

| Mode | DNS resolve | TCP connect | Exec used? | When to use |
|---|---|---|---|---|
| `auto` (default) | ✅ | ✅ | yes | interactive debugging |
| `api` | ❌ (skip) | ❌ (skip) | no | CI, or no `pods/exec` RBAC |
| `tcp` | — | ✅ (forced) | yes | force the handshake even when auto would skip |
| `dns` | ✅ | — | yes | only resolve, skip TCP |

`--no-exec` is a shortcut equivalent to `--probe=api`.

### Opt-in deepening flags

| Flag | Hop | What it adds |
|---|---|---|
| `--inspect-rules` | 7a. Rules | exec the **kube-proxy pod on the source node** and grep the ClusterIP in `ipvsadm -Ln` (ipvs), `iptables-save` (iptables), or `nft list ruleset` (nft). FAIL = the node isn't programmed for this Service yet. Needs `pods/exec` on `kube-system`. |
| `--mtu-probe` | 7b. Path-MTU | binary-search df-ping (`ping -M do -s N`) from the source Pod to the target IP; reports the largest unfragmented payload + implied path MTU. Catches overlay/VPN MTU-mismatch blackholes. |
| `--debug-container` | 6b. Debug Container | inject an ephemeral `nicolaka/netshoot` container into the source Pod so probes work on stripped/distroless images. Needs the `ephemeralcontainers` RBAC subresource; after injection, re-run `knm trace` to probe via the new container. |

All three default off. Each degrades to SKIP/WARN (never FAIL-crash) when its
prerequisite is missing.

---

## How active probes degrade gracefully

knm never crashes when exec is unavailable. The decision tree for each active
hop:

1. `--no-exec` / `--probe=api` → hop is **SKIP** with a note.
2. exec transport error (no `pods/exec` RBAC, pod not Running) → hop is **WARN**
   with the underlying error.
3. exec runs but the image has no resolver/connect tool → the probe script tries
   `getent → nslookup` (DNS) and `nc → bash /dev/tcp → python3 → wget → curl`
   (TCP). If **all** are missing the command exits non-zero → hop is FAIL/WARN
   with the captured stderr snippet.

This mirrors the whole CLI's contract: a command always produces real output or
a clear reason, never a silent no-op.

### Tool detection order

**DNS resolve** (`sh -c`):
1. `getent hosts <fqdn>` — glibc images, no extra deps
2. `nslookup <fqdn>` + awk — busybox/alpine
3. exit 3 = nothing worked

**TCP connect** (`sh -c`, host:port passed as `$1`):
1. `nc -z -w<timeout>` — busybox + traditional netcat
2. `bash -c 'exec 3<>/dev/tcp/$host/$port'`
3. `python3` with `socket.create_connection`
4. `wget --spider`
5. `curl --connect-timeout`
6. exit 1 = all failed

---

## RBAC

Active probing requires **`pods/exec`** on the source Pod's namespace. If your
kubeconfig user lacks it, the probes degrade to WARN automatically; no special
error handling is needed. The `NetworkPolicy` and all read-only hops need only
`get`/`list` on pods, services, endpointslices, networkpolicies, daemonsets.

---

## Output formats

| `-o` | What you get |
|---|---|
| `table` (default) | one row per hop with STATUS + DETAIL |
| `wide` | adds the exec stdout snippet / degrade note column |
| `json` / `yaml` | structured hops (machine-readable) |
| `dot` / `mermaid` | the hop chain rendered as a left-to-right **path graph**; FAIL edges are labelled `broken` |

Example path graph:
```
knm trace pod/web svc/api -o mermaid
```
```
flowchart LR
  00_source_pod["Source Pod<br/>(OK)"] --> 01_dns["DNS<br/>(OK)"]
  01_dns --> 02_networkpolicy["NetworkPolicy<br/>(OK)"]
  02_networkpolicy --> 03_service["Service<br/>(OK)"]
  03_service --> 04_endpoints["Endpoints<br/>(OK)"]
  04_endpoints --> 05_tcp_connect["TCP Connect<br/>(OK)"]
  ...
```
Paste mermaid into any renderer, or pipe dot through Graphviz:
`knm trace pod/web svc/api -o dot | dot -Tsvg > trace.svg`.

---

## Validate on a local kind cluster

```bash
# 1. bring up kind and a demo app
kind create cluster
kubectl run web --image=nginx --port=80
kubectl expose pod web --port=80
kubectl run debug --image=nicolaka/netshoot -- sleep 1h   # has nc/curl/getent

# 2. happy path (auto probe)
make build
./bin/knm trace pod/debug svc/web
# Expect: all OK, including DNS resolve → ClusterIP and TCP Connect → connected

# 3. simulate a broken Service (scale to 0 endpoints)
kubectl delete pod web
./bin/knm trace pod/debug svc/web
# Expect: Endpoints FAIL (0 ready backing pods) — break here

# 4. pure read-only walk (CI mode)
./bin/knm trace pod/debug svc/web --probe=api
# Expect: DNS/TCP hops SKIP, NetworkPolicy verdict still computed

# 5. path graph
./bin/knm trace pod/debug svc/web -o mermaid

# 6. deep probing: rules + path-MTU (the kube-proxy pod has ipvsadm/iptables)
./bin/knm trace pod/debug svc/web --inspect-rules --mtu-probe
# Expect: kube-proxy rules OK (ClusterIP present), Path-MTU = 1500 (kind NAT)

# 7. debug-container injection (for distroless sources)
kubectl run distroless --image=gcr.io/distroless/static-debian12 -- /nonexistent
./bin/knm trace pod/distroless svc/web --debug-container
# Expect: Debug Container OK, then re-run to probe via the netshoot sidecar
```

---

## Architecture

The tracer is split so the logic is fully unit-testable without a cluster:

```
internal/trace/        pure logic over fetched API objects + ExecClient
  probe.go             ExecClient interface, ProbeMode, NoExec sentinel
  probe_scripts.go     the sh -c DNS/TCP probe bodies (tool auto-detect)
  trace.go             Run() orchestrator + every hop helper
  trace_test.go        fake clientset + fake ExecClient, full chain coverage
internal/kube/
  exec.go              RemoteExecutor: remotecommand SPDY impl of ExecClient
internal/cli/
  trace.go             cobra wiring: flags, render, dot/mermaid graph
```

`trace.ExecClient` is the seam: production uses `kube.RemoteExecutor`, tests
inject a fake that returns canned stdout per probe type. This is the
reference pattern for making the rest of the CLI's logic testable too.
