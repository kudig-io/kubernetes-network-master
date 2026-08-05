package gateway

import (
	"encoding/json"
	"fmt"

	netv1 "k8s.io/api/networking/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

// LoadIngresses parses one or more Ingress YAML/JSON documents (single object,
// List, or multi-doc stream).
func LoadIngresses(raw []byte) ([]netv1.Ingress, error) {
	// Try List.
	var list struct {
		Items []netv1.Ingress `json:"items"`
	}
	if err := yaml.Unmarshal(raw, &list); err == nil && len(list.Items) > 0 {
		return list.Items, nil
	}
	// Try single object / multi-doc stream.
	var out []netv1.Ingress
	for _, d := range splitDocs(raw) {
		if len(d) == 0 {
			continue
		}
		jb, err := yaml.YAMLToJSON(d)
		if err != nil {
			jb = d
		}
		var ing netv1.Ingress
		if err := json.Unmarshal(jb, &ing); err == nil && ing.Name != "" {
			out = append(out, ing)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no Ingress documents found in input")
	}
	return out, nil
}

// LoadGatewayAPISet parses Gateway API YAML (Gateways, HTTPRoutes) for linting.
func LoadGatewayAPISet(raw []byte) (LintSet, error) {
	set := LintSet{}
	for _, d := range splitDocs(raw) {
		if len(d) == 0 {
			continue
		}
		jb, err := yaml.YAMLToJSON(d)
		if err != nil {
			jb = d
		}
		var meta struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(jb, &meta)
		switch meta.Kind {
		case "Gateway":
			var gw gwapiv1.Gateway
			if err := json.Unmarshal(jb, &gw); err == nil {
				set.Gateways = append(set.Gateways, gw)
			}
		case "HTTPRoute":
			var rt gwapiv1.HTTPRoute
			if err := json.Unmarshal(jb, &rt); err == nil {
				set.HTTPRoutes = append(set.HTTPRoutes, rt)
			}
		case "Service":
			// populate ServicesByNN for backend ref checks
			var ref struct {
				Metadata struct {
					Namespace string `json:"namespace"`
					Name      string `json:"name"`
				} `json:"metadata"`
			}
			_ = json.Unmarshal(jb, &ref)
			if set.ServicesByNN == nil {
				set.ServicesByNN = map[string]struct{}{}
			}
			set.ServicesByNN[ref.Metadata.Namespace+"/"+ref.Metadata.Name] = struct{}{}
		}
	}
	return set, nil
}

func splitDocs(raw []byte) [][]byte {
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
