package trace

import (
	"fmt"
	"time"
)

// dnsResolveCmd builds a shell command that resolves a name using whatever
// resolver the image has. We try, in priority order:
//
//	getent hosts <name>           (glibc images, no extra deps)
//	nslookup <name> | grep ..     (busybox/alpine)
//	nc -w1 <dnsip> 53 </dev/null  (last resort — just reach CoreDNS)
//
// It is wrapped in `sh -c` so a single exec call probes multiple tools. The
// first one that succeeds (exit 0) wins; output is whichever printed IPs.
func dnsResolveCmd(fqdn string) []string {
	script := fmt.Sprintf(`
set +e
ips=$(getent hosts %q 2>/dev/null | awk '{print $1}')
if [ -n "$ips" ]; then echo "$ips"; exit 0; fi
ips=$(nslookup %q 2>/dev/null | awk '/^Address:|Name:/ && $0 !~ /#53$/ {print $NF}')
if [ -n "$ips" ]; then echo "$ips"; exit 0; fi
exit 3
`, fqdn, fqdn)
	return []string{"sh", "-c", script}
}

// tcpConnectCmd builds a shell command that attempts a TCP connect to addr
// (host:port) using the first available of: nc, bash /dev/tcp, python3,
// wget --spider, curl. Returns exit 0 on success, non-zero otherwise.
//
// The whole probe is one `sh -c` so a stripped image still gets covered if it
// has any one of these tools. We prefer `nc -z -w` (busybox + traditional).
func tcpConnectCmd(addr string, timeout time.Duration) []string {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	script := fmt.Sprintf(`
set +e
host=${1%%:*}; port=${1#*:}
nc -z -w%d "$host" "$port" 2>/dev/null && exit 0
if command -v bash >/dev/null 2>&1; then
  timeout %d bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null && exit 0
fi
if command -v python3 >/dev/null 2>&1; then
  timeout %d python3 -c "import socket,sys; socket.socket().settimeout(%d); socket.create_connection(('$host',$port),%d).close()" 2>/dev/null && exit 0
fi
if command -v wget >/dev/null 2>&1; then
  timeout %d wget -q -T%d -t1 --spider "http://$host:$port/" 2>/dev/null && exit 0
fi
if command -v curl >/dev/null 2>&1; then
  timeout %d curl -s -o /dev/null --connect-timeout %d "http://$host:$port/" 2>/dev/null && exit 0
fi
exit 1
`, secs, secs, secs, secs, secs, secs, secs, secs, secs)
	// Pass addr as $1 so the shell parses host/port safely.
	return []string{"sh", "-c", script, "tcpconnect", addr}
}

// rulesCmd builds a shell command that inspects kube-proxy's data plane rules
// for a specific ClusterIP. It probes ipvsadm first (ipvs mode), then
// iptables-save (iptables mode). It returns the matching rule lines on stdout
// (exit 0 = rules present, exit 1 = no matching rule, exit 3 = no tool).
//
// The ClusterIP is passed as $1. We grep for the IP so a missing/unsynced rule
// surfaces as a non-zero exit.
func rulesCmd(clusterIP string) []string {
	script := `
set +e
ip=$1
# ipvs mode: ipvsadm -Ln lists virtual services; grep the IP.
if command -v ipvsadm >/dev/null 2>&1; then
  hits=$(ipvsadm -Ln 2>/dev/null | grep "$ip")
  if [ -n "$hits" ]; then echo "ipvs:"; echo "$hits"; exit 0; fi
  echo "ipvs: no rule for $ip"; exit 1
fi
# iptables mode: iptables-save greps for the IP across all chains.
if command -v iptables >/dev/null 2>&1; then
  hits=$(iptables-save 2>/dev/null | grep "$ip")
  if [ -n "$hits" ]; then echo "iptables:"; echo "$hits"; exit 0; fi
  echo "iptables: no rule for $ip"; exit 1
fi
# nftables fallback (kube-proxy can use nft on newer kernels).
if command -v nft >/dev/null 2>&1; then
  hits=$(nft list ruleset 2>/dev/null | grep "$ip")
  if [ -n "$hits" ]; then echo "nft:"; echo "$hits"; exit 0; fi
  echo "nft: no rule for $ip"; exit 1
fi
exit 3
`
	return []string{"sh", "-c", script, "rules", clusterIP}
}

// MTUProbeCmd builds a shell command that performs a path-MTU discovery by
// binary-searching the DF-ping payload size. It starts at 1472 (typical for a
// 1500-byte link) and halves until a "do not fragment" ping succeeds, then
// reports the largest succeeding payload and the implied path MTU.
//
// dst IP is $1. Tries `ping -M do -s N` (Linux iputils), then `ping -D -s N`
// (busybox, no -M). Exit 0 with the number on stdout; exit 1 if no ping at
// all; exit 3 if the link fragments at every tested size (path-MTU < 28).
//
// Exported so other commands (e.g. knm mc connectivity) can reuse it.
func MTUProbeCmd(dst string) []string {
	return mtuProbeCmd(dst)
}

// mtuProbeCmd builds a shell command that performs a path-MTU discovery by
// binary-searching the DF-ping payload size. It starts at 1472 (typical for a
// 1500-byte link) and halves until a "do not fragment" ping succeeds, then
// reports the largest succeeding payload and the implied path MTU.
//
// dst IP is $1. Tries `ping -M do -s N` (Linux iputils), then `ping -D -s N`
// (busybox, no -M). Exit 0 with the number on stdout; exit 1 if no ping at
// all; exit 3 if the link fragments at every tested size (path-MTU < 28).
func mtuProbeCmd(dst string) []string {
	script := `
set +e
dst=$1
# pick a ping invocation that supports DF
dfping() {
  ping -c 1 -M do -s "$1" "$dst" >/dev/null 2>&1 && return 0
  ping -c 1 -D -s "$1" "$dst" >/dev/null 2>&1 && return 0
  return 1
}
# verify ping exists at all
command -v ping >/dev/null 2>&1 || { echo 0; exit 1; }
lo=0; hi=1472; best=0
while [ "$lo" -le "$hi" ]; do
  mid=$(( (lo + hi) / 2 ))
  if dfping "$mid"; then
    best=$mid
    lo=$(( mid + 1 ))
  else
    hi=$(( mid - 1 ))
  fi
done
if [ "$best" -eq 0 ]; then echo 0; exit 3; fi
# payload + 28 bytes ICMP/IP header = effective path MTU
echo $(( best + 28 ))
exit 0
`
	return []string{"sh", "-c", script, "mtu", dst}
}
