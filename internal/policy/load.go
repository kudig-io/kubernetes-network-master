package policy

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"
)

// LoadPoliciesFromBytes parses one or more YAML/JSON NetworkPolicy documents.
// The input may be a single object, a List, or a multi-document YAML stream.
func LoadPoliciesFromBytes(raw []byte) ([]netv1.NetworkPolicy, error) {
	// Try a List first (kubectl-style).
	var list corev1.List
	if err := yaml.Unmarshal(raw, &list); err == nil && len(list.Items) > 0 {
		var out []netv1.NetworkPolicy
		for _, it := range list.Items {
			p, err := decodePolicy(it.Raw)
			if err == nil {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	// Try single object.
	if p, err := decodePolicy(raw); err == nil && p.Name != "" {
		return []netv1.NetworkPolicy{p}, nil
	}
	// Try multi-doc YAML stream.
	docs := splitYAMLDocs(raw)
	var out []netv1.NetworkPolicy
	for _, d := range docs {
		if len(d) == 0 {
			continue
		}
		if p, err := decodePolicy(d); err == nil && p.Name != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no NetworkPolicy documents found in input")
	}
	return out, nil
}

func decodePolicy(raw []byte) (netv1.NetworkPolicy, error) {
	jsonBytes, err := yaml.YAMLToJSON(raw)
	if err != nil {
		// Maybe it was already JSON.
		jsonBytes = raw
	}
	var p netv1.NetworkPolicy
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return p, err
	}
	return p, nil
}

func splitYAMLDocs(raw []byte) [][]byte {
	// YAML documents separated by "\n---" lines.
	docs := [][]byte{}
	current := []byte{}
	lines := splitLines(string(raw))
	for _, line := range lines {
		if line == "---" {
			docs = append(docs, current)
			current = []byte{}
			continue
		}
		current = append(current, []byte(line+"\n")...)
	}
	docs = append(docs, current)
	return docs
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// LoadFlowsFromBytes parses an observed-flow dump (YAML or JSON) into a slice
// of ObservedFlow. The dump may be a list under top-level "flows:" or a JSON
// array.
func LoadFlowsFromBytes(raw []byte) ([]ObservedFlow, error) {
	// Normalize YAML→JSON.
	jsonBytes, err := yaml.YAMLToJSON(raw)
	if err != nil {
		jsonBytes = raw
	}
	// Try {"flows":[...]}.
	wrapped := struct {
		Flows []ObservedFlow `json:"flows"`
	}{}
	if err := json.Unmarshal(jsonBytes, &wrapped); err == nil && len(wrapped.Flows) > 0 {
		return wrapped.Flows, nil
	}
	// Try bare array.
	var arr []ObservedFlow
	if err := json.Unmarshal(jsonBytes, &arr); err == nil {
		return arr, nil
	}
	return nil, fmt.Errorf("could not parse observed flows (expected {flows:[...]} or a JSON array)")
}
