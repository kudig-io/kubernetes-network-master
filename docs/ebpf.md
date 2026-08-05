# eBPF backend — design & roadmap

## Goal

Provide zero-instrument, Pod-level network visibility that is **CNI-agnostic**
(the lightweight alternative to Cilium Hubble, which is tightly coupled to the
Cilium CNI). Commands that depend on it:

- `knm observe flows` — live TCP connections per Pod
- `knm observe events` — packet loss / retransmit / latency tail events
- `knm security baseline` — learn each Pod's normal peers, alert on deviation
- `knm policy generate --from-flows` — synthesize least-privilege NetworkPolicies
- `knm gpu analyze` — RDMA/RoCE link-level stats + NCCL-test correlation

## Current state (this build)

There is **no compiled eBPF bytecode** in this release. `internal/ebpf` exposes:

```go
type Status struct { Available bool; Reason string }
func Availability() Status   // non-Linux → unavailable; Linux → "backend not enabled"
func Degrade(feature string) string
```

Every eBPF-dependent command calls `Availability()` first and, when false,
prints `Degrade(feature)` and continues with an API-level fallback instead of
crashing. This keeps the binary buildable and runnable on macOS / dev laptops.

## Roadmap

1. **Capability detection (Linux)** — read `/proc/self/status` for
   `Cap_BPF`/`Cap_NET_ADMIN`, check kernel ≥ 5.13 for CO-RE.
2. **Backend choice** — prefer `libbpf-go` (CGO) for maturity; ship a
   build-tagged `ebpf_linux.go` so non-Linux builds still compile.
3. **Programs**:
   - `kprobe:tcp_connect` / `fentry:tcp_v4_connect` → connection open
   - `tracepoint:sock:inet_sock_set_state` → connection state changes
   - `kprobe:tcp_retransmit_skb` → retransmissions
   - `tracepoint:skb:kfree_skb` → packet drops (with reason)
   - XDP/TC on pod veth → per-pod counters (loss, bytes, rtt via `tcp_sock`)
4. **Pod resolution** — attach socket cookie → cgroup id → Pod via the
   container runtime socket → Pod mapping (avoid hard CNI coupling).
5. **Export** — ring buffer → userspace aggregator → the existing
   `internal/output` renderer (so `-o json/table` works unchanged).
6. **Safety** — pin maps, set rlimits, drop caps after load, bounded event
   rates, and a hard CPU/memory budget (Hubble's #1 complaint is weight).

## Degrade contract (must hold post-backend)

For each eBPF command, the fallback path remains the "still useful" answer:

| Command | Full eBPF path | Fallback (current) |
|---|---|---|
| `observe flows` | live per-Pod TCP flows | static service map from API |
| `observe events` | streamed loss/retransmit | empty + roadmap note |
| `security baseline` | learned peer baseline | per-Pod metadata table |
| `policy generate` | least-privilege from observed flows | default-deny template |
| `gpu analyze` | RDMA NIC + NCCL stats | empty + roadmap note |

The contract: a command **never** silently does nothing. It either produces
real output or a clear `ℹ not yet implemented:` / degrade note explaining why.
