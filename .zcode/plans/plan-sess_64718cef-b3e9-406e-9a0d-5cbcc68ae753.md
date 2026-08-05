# 全量完成:trace 三深化 + SHALLOW 命令补齐 + 文档

## 分层与优先级

### 第一层:trace 三个深化(你点名要的,优先级最高)

接入点已确认:v0.30.4 同时支持 kube-proxy 节点级 pod 查找(`AppsV1().DaemonSets` + `CoreV1().Pods` fieldSelector `spec.nodeName`)和 ephemeral containers(`corev1.EphemeralContainer` + `UpdateEphemeralContainers`,fake clientset 也支持 → 可单测)。

**A. iptables/ipvs 规则检查** — `rulesHop`
- 新 `trace.Options.InspectRules bool` + cli flag `--inspect-rules`
- 找到源 Pod 所在节点的 kube-proxy DaemonSet pod;若 `--inspect-rules` 开启,exec 进该 pod:
  - ipvs 模式:`ipvsadm -Ln | grep <ClusterIP>` → 命中行数
  - iptables 模式:`iptables-save | grep <ClusterIP>` → 命中链
- ClusterIP 命中规则为 OK,零命中为 FAIL(`kube-proxy 规则未同步`)。降级:无 exec 权限/找不到 pod → WARN + 原因
- 替换 `proxyHop` 现有 `(rule inspection TODO)` 字样

**B. path-MTU / df-ping 探测** — `pathMtuHop`
- 新 `trace.Options.MTUProbe bool` + cli flag `--mtu-probe`
- 新 `mtuProbeCmd(dstIP)`:在源 Pod exec 二分法 `ping -M do -s <size>`,从 1472 递减找到不分的最大 payload;失败(无 ping)降级到 WARN
- 输出 "PMTU=1408 bytes (effective MTU 1428)" 或降级原因
- 复用既有 `tcpConnectHop` 的多工具嗅探模式

**C. Ephemeral debug 容器注入** — `debugContainerHop`
- 新 `trace.Options.DebugContainer bool` + cli flag `--debug-container`
- 当源 Pod 镜像无探测工具时(`tcpConnectHop`/`dnsHop` 反复失败 + `--debug-container`):注入一个 ephemeral `nicolaka/netshoot` 容器到源 Pod,等待 Running,然后用它作为 exec 载体重跑 DNS/TCP 探测
- 需要 `Factory.Config()`(已暴露)+ `UpdateEphemeralContainers`;包一个 `EphemeralInjector` 接口便于测试(fake 实现)
- 这是"零工具镜像"(distroless)的逃生路径;默认关闭(需 ephemeralcontainers RBAC),开失败时明确降级提示

**hop 链新顺序:**
```
1 Source Pod → 2 DNS → 3 NetworkPolicy → 4 Service → 5 Endpoints
→ 6 TCP Connect → 7 kube-proxy → 8 [NEW] Rules → 9 [NEW] Path-MTU
→ 10 CNI → 11 Target Pod   (+ debug-container 作为 TCP/DNS 失败时的旁路)
```

**新测试:** `internal/trace/rules_test.go`(fake kube-proxy pod + fake exec 返回 ipvsadm 输出)、`mtu_test.go`(fake ping 输出)、`ephemeral_test.go`(fake injector)。

### 第二层:无 eBPF 依赖的 SHALLOW 命令补齐(可纯逻辑/普通集群验证)

按"杠杆率"排序,本轮补齐这些(全部能在普通集群或纯文件输入下端到端跑通,不依赖 libbpf):

| 命令 | 现状 | 本轮补齐 |
|---|---|---|
| **gateway replay** | 纯 stub | 从 access-log 文件(`-f`)或 HAR 回放请求到目标 Gateway URL,统计状态码/延迟分布,与基线 `-o` 对比。纯 Go HTTP,可单测 |
| **cni bench** | 方法论清单 | 实跑:创建两个 iperf3 pod,等 Ready,服务端起 `iperf3 -s`,客户端 `iperf3 -c`,解析吞吐/延迟,p50/p99。失败优雅降级到方法论 |
| **cni fault** | 静态目录 | 生成可执行的注入清单:为每个场景产出 `kubectl exec` 命令或 chaos-mesh `NetworkChaos` YAML(`-o yaml`)。可复制即用 |
| **cni drift** | baseline | 增加实际探测快照:exec 节点统计 iptables 规则数/路由条数/接口数,存为快照,二次运行时 diff |
| **security dns** | 找 pod | 抓 CoreDNS Prometheus 指标(`:9153/metrics`),解析 per-zone query count / cache miss / 错误率。无 prometheus 时降级 |
| **security baseline** | labels | 从 EndpointSlice + Service 构建每个 Pod 的"可达性基线"(能被哪些 svc 访问),作为非 eBPF 的初版基线 |
| **gpu analyze** | 空 | 解析 `nccl-test` 日志文件(`-f`),按 latency/ALGO BW 排序 rank,标出最慢链路。与 `policy generate --from-flows` 同构 |
| **gpu qos** | 硬编码行 | 读节点 annotation/deviceclass,推导实际 QoS 状态(已知标注 vs 未配置) |
| **mc connectivity** | baseline | 在多上下文中各跑一次 in-cluster MTU/连通探测(复用 trace 的 exec 能力) |
| **observe events** | 空 | 降级路径改为流式读取 Kubernetes Events(过滤 network 相关 reason:FailedScheduling/Unhealthy/TrafficPolicy 等),eBPF 路径保持 roadmap |
| **sandbox** | detect | 实跑:`kind create cluster --name knm-sandbox`(或 k3d),装多 CNI 教程占位 |
| **policy generate** | 修一个 bug | `--from-flows` 成功时不应再打印 "live eBPF capture NYI"(因为 flows 来自文件,非缺失) |

### 第三层:eBPF 依赖项(保持降级,但优化降级输出)
`observe flows`(libbpf 流)、`security baseline`(eBPF 学习)、`gpu analyze`(RDMA eBPF)—— 真实 libbpf-go 后端本轮不做(需 Linux 内核 + CGO,macOS 无法验证),但:
- 第二层已为这些提供了**有意义的非 eBPF 降级实现**(service map / 可达性基线 / nccl-log 解析),不再是空表
- `docs/ebpf.md` 更新降级矩阵,标注"已有降级实现"

### 架构原则(贯穿)
- 纯逻辑包 + `cli` 薄层 + 接口注入(沿用 `trace` 树立的范式):每个深化的命令尽量把可测逻辑抽到 `internal/<domain>/`,cli 只做 flag 解析 + render
- 所有 exec 都走既有 `ExecClient` 接口;新引入的外部依赖(HTTP client for replay/prometheus、HAR 解析)用小接口包裹便于 fake
- 降级契约不变:任何探测不可用时给 WARN/SKIP + 明确原因,不崩溃
- 每个深化的纯逻辑点配单测

### 文档同步
- `docs/trace.md`:新增 Rules / Path-MTU / Debug Container 三节,更新 hop 链图、flag 表、kind 验证步骤
- `docs/commands.md`:逐命令更新 Done/Roadmap 状态
- `README.md`:命令表状态列全面更新
- `docs/ebpf.md`:更新降级矩阵(标注已有非 eBPF 降级实现)

## 验收
- `go build` / `go vet` / `gofmt` / `go test` 全绿
- 新增纯逻辑测试覆盖:rules hop、MTU、ephemeral、replay 解析、cni bench 解析、nccl 解析、dns metrics 解析
- 现有命令无回归
- README/commands/trace 文档与实现一致

## 不在本轮(明确)
- 真实 libbpf-go eBPF 字节码后端(Linux 内核 + CGO,需 Linux 环境验证,单独一轮)
- chaos-mesh / litmus 的实际注入执行(只生成清单,不执行破坏性操作)
- 完整的 ReferenceGrant/Gateway API 流量录制生产级方案(replay 做到 access-log/HAR 回放级)