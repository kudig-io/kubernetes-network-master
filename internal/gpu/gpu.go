// Package gpu implements GPU-network analysis: parsing NCCL-test output to
// rank slow AllReduce links, and deriving RDMA QoS state from node annotations.
// Pure logic over inputs (log text / node annotations), so it's unit-testable
// without a GPU cluster.
package gpu

import (
	"bufio"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// NCCLLine is one parsed NCCL-test measurement (avg latency + algo bandwidth).
type NCCLLine struct {
	Size       string  // message size, e.g. "1B", "8M"
	AvgLatency float64 // microseconds
	AlgoBW     float64 // GB/s
	Line       int
}

// NCCLReport aggregates parsed NCCL-test output, highlighting the slowest
// operations (lowest bandwidth / highest latency) which point at the
// bottleneck node/link.
type NCCLReport struct {
	Lines      []NCCLLine
	SlowestBW  NCCLLine // lowest algo bandwidth (worst throughput)
	SlowestLat NCCLLine // highest latency
}

// ParseNCCLLog parses nccl-test stdout. The canonical output has columns like:
//
//	#       size    count   type  redop   time  algbw  busbw ...
//	       (B)    (elements)            (us)  (GB/s) (GB/s)
//	        1         1  float    sum   xx.x   0.00   0.00
//
// We scan for the trailing numeric columns; lines we can't parse are skipped.
func ParseNCCLLog(raw string) *NCCLReport {
	rep := &NCCLReport{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Fields(line)
		// We need at least size + time + algbw. Column layout varies, so we
		// take the size token and scan right-to-left for numeric BW/latency.
		if len(fields) < 4 {
			continue
		}
		l, ok := parseNCCLFields(fields, lineNo)
		if !ok {
			continue
		}
		rep.Lines = append(rep.Lines, l)
	}
	if len(rep.Lines) == 0 {
		return rep
	}
	// Find slowest.
	rep.SlowestBW = rep.Lines[0]
	rep.SlowestLat = rep.Lines[0]
	for _, l := range rep.Lines[1:] {
		if l.AlgoBW < rep.SlowestBW.AlgoBW {
			rep.SlowestBW = l
		}
		if l.AvgLatency > rep.SlowestLat.AvgLatency {
			rep.SlowestLat = l
		}
	}
	// Sort by bandwidth ascending so the slowest are at the top.
	sort.Slice(rep.Lines, func(i, j int) bool { return rep.Lines[i].AlgoBW < rep.Lines[j].AlgoBW })
	return rep
}

// parseNCCLFields pulls size (fields[0]), and scans the last numeric tokens
// for latency + algo bandwidth. NCCL-test reliably puts algbw before busbw,
// and time before algbw; we take the last three numerics as (time, algbw, busbw)
// when there are enough, else the last numeric as algbw.
func parseNCCLFields(fields []string, lineNo int) (NCCLLine, bool) {
	size := fields[0]
	// collect trailing numeric tokens
	var nums []float64
	for i := len(fields) - 1; i >= 0 && len(nums) < 4; i-- {
		f, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			// stop at the first non-numeric token scanning right-to-left
			if len(nums) > 0 {
				break
			}
			continue
		}
		nums = append(nums, f)
	}
	if len(nums) == 0 {
		return NCCLLine{}, false
	}
	// nums are in reverse order: [busbw?, algbw?, time?, ...]
	l := NCCLLine{Size: size, Line: lineNo}
	switch {
	case len(nums) >= 3:
		l.AvgLatency = nums[2]
		l.AlgoBW = nums[1]
	case len(nums) == 2:
		l.AvgLatency = nums[1]
		l.AlgoBW = nums[0]
	default:
		l.AlgoBW = nums[0]
	}
	if l.AlgoBW <= 0 && l.AvgLatency <= 0 {
		return NCCLLine{}, false
	}
	return l, true
}

// QoSState describes a node's RDMA QoS posture, derived from annotations.
type QoSState struct {
	Node       string
	Configured bool   // any known QoS annotation/device-class present
	Priority   string // e.g. "P1" when RDMA prioritized
	Details    string
}

// known QoS annotation keys (Multus / SR-IOV / RoCE device plugins).
var qosAnnotationKeys = []string{
	"rdma.qos",
	"roce.qos",
	"sriovnetwork.openshift.io/interface",
	"k8s.v1.cni.cncf.io/networks",
	"mellanox.com/cx5-rdma",
	"intel.com/sriov",
}

// DeriveQoS inspects node annotations + capacity to report whether RDMA QoS
// is configured. This is a best-effort, CNI/plugin-specific heuristic.
func DeriveQoS(node corev1.Node) QoSState {
	s := QoSState{Node: node.Name, Priority: "P3 (best-effort)"}
	var details []string
	for _, key := range qosAnnotationKeys {
		if v, ok := node.Annotations[key]; ok {
			s.Configured = true
			details = append(details, fmt.Sprintf("%s=%s", key, v))
			if strings.Contains(strings.ToLower(key), "rdma") || strings.Contains(strings.ToLower(key), "roce") {
				s.Priority = "P1 (high)"
			}
		}
	}
	// GPU capacity presence.
	if q, ok := node.Status.Capacity["nvidia.com/gpu"]; ok && q.Value() > 0 {
		details = append(details, fmt.Sprintf("gpu=%d", q.Value()))
	}
	s.Details = strings.Join(details, "; ")
	if !s.Configured {
		s.Details = "no RDMA/QoS annotations; default best-effort"
	}
	return s
}
