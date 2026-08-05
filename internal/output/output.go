// Package output is the single rendering layer for knm-cli. Every command
// produces Rows and selects a Format; this package knows how to emit JSON,
// YAML, a table, a wide table, a Graphviz DOT graph, or a Mermaid graph.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/yaml"
)

// Format is the rendering style selected by -o.
type Format string

const (
	FormatTable   Format = "table"
	FormatWide    Format = "wide"
	FormatJSON    Format = "json"
	FormatYAML    Format = "yaml"
	FormatDot     Format = "dot"
	FormatMermaid Format = "mermaid"
)

// ParseFormat normalizes a user-supplied -o value. Unknown values default to
// FormatTable.
func ParseFormat(s string) Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "table":
		return FormatTable
	case "wide":
		return FormatWide
	case "json":
		return FormatJSON
	case "yaml":
		return FormatYAML
	case "dot", "graphviz":
		return FormatDot
	case "mermaid", "mmd":
		return FormatMermaid
	default:
		return FormatTable
	}
}

// Cell is a single value with optional wide-form detail. When a command
// renders in -o wide, the Wide value (if non-empty) is appended to its base
// Value in its own column.
type Cell struct {
	Value string
	Wide  string
}

// Row is one record. Column order follows Headers.
type Row map[string]Cell

// Table holds everything needed to render in any format.
type Table struct {
	Title   string   // optional, shown above tables / used as graph label
	Headers []string // column order
	Rows    []Row
	Graph   *Graph   // optional; used for dot/mermaid when set
	Notes   []string // human notes appended under the table (e.g. "ℹ not yet implemented: ...")
}

// Graph is an optional node/edge set for dot/mermaid rendering.
type Graph struct {
	Label string
	Nodes []GraphNode
	Edges []GraphEdge
}

// GraphNode is a vertex in a dependency / topology graph.
type GraphNode struct {
	ID    string
	Label string
	Kind  string // e.g. "Service", "Pod", "Namespace"
}

// GraphEdge is a directed relationship.
type GraphEdge struct {
	From  string
	To    string
	Label string
}

// Render writes the table in the requested format to w.
func Render(w io.Writer, t *Table, format Format) error {
	switch format {
	case FormatJSON:
		return renderJSON(w, t)
	case FormatYAML:
		return renderYAML(w, t)
	case FormatDot:
		return renderDot(w, t)
	case FormatMermaid:
		return renderMermaid(w, t)
	default:
		wide := format == FormatWide
		return renderTable(w, t, wide)
	}
}

// --- structured (json/yaml) ---

type flatTable struct {
	Title   string              `json:"title,omitempty"`
	Headers []string            `json:"headers,omitempty"`
	Rows    []map[string]string `json:"rows,omitempty"`
	Graph   *flatGraph          `json:"graph,omitempty"`
	Notes   []string            `json:"notes,omitempty"`
}
type flatGraph struct {
	Label string      `json:"label,omitempty"`
	Nodes []GraphNode `json:"nodes,omitempty"`
	Edges []GraphEdge `json:"edges,omitempty"`
}

func flatten(t *Table, wide bool) *flatTable {
	out := &flatTable{Title: t.Title, Notes: t.Notes}
	if len(t.Headers) > 0 {
		out.Headers = append([]string{}, t.Headers...)
	}
	for _, r := range t.Rows {
		m := map[string]string{}
		for _, h := range t.Headers {
			c, ok := r[h]
			if !ok {
				continue
			}
			if wide && c.Wide != "" {
				m[h] = c.Value + "  " + c.Wide
			} else {
				m[h] = c.Value
			}
		}
		out.Rows = append(out.Rows, m)
	}
	if t.Graph != nil {
		out.Graph = &flatGraph{Label: t.Graph.Label, Nodes: t.Graph.Nodes, Edges: t.Graph.Edges}
	}
	return out
}

func renderJSON(w io.Writer, t *Table) error {
	b, err := json.MarshalIndent(flatten(t, true), "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

func renderYAML(w io.Writer, t *Table) error {
	b, err := yaml.Marshal(flatten(t, true))
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w, string(b))
	return err
}

// --- tables ---

func renderTable(w io.Writer, t *Table, wide bool) error {
	if t.Title != "" {
		fmt.Fprintln(w, t.Title)
	}
	if len(t.Rows) == 0 {
		fmt.Fprintln(w, "(no results)")
	} else if len(t.Headers) > 0 {
		tw := tablewriter.NewWriter(w)
		tw.SetHeader(t.Headers)
		tw.SetAutoWrapText(false)
		tw.SetAutoFormatHeaders(true)
		tw.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		tw.SetAlignment(tablewriter.ALIGN_LEFT)
		for _, r := range t.Rows {
			row := make([]string, 0, len(t.Headers))
			for _, h := range t.Headers {
				c := r[h]
				val := c.Value
				if wide && c.Wide != "" {
					val = c.Value + "  " + c.Wide
				}
				row = append(row, val)
			}
			tw.Append(row)
		}
		tw.Render()
	}
	for _, n := range t.Notes {
		fmt.Fprintln(w, n)
	}
	return nil
}

// --- graphs ---

func renderDot(w io.Writer, t *Table) error {
	g := t.Graph
	label := t.Title
	if g != nil && g.Label != "" {
		label = g.Label
	}
	fmt.Fprintf(w, "digraph %q {\n", label)
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [shape=box, style=rounded];")
	if g != nil {
		// stable node order
		nodes := append([]GraphNode{}, g.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for _, n := range nodes {
			fmt.Fprintf(w, "  %q [label=\"%s\\n(%s)\"];\n", n.ID, n.Label, n.Kind)
		}
		for _, e := range g.Edges {
			if e.Label != "" {
				fmt.Fprintf(w, "  %q -> %q [label=%q];\n", e.From, e.To, e.Label)
			} else {
				fmt.Fprintf(w, "  %q -> %q;\n", e.From, e.To)
			}
		}
	}
	fmt.Fprintln(w, "}")
	return nil
}

func renderMermaid(w io.Writer, t *Table) error {
	g := t.Graph
	label := t.Title
	if g != nil && g.Label != "" {
		label = g.Label
	}
	fmt.Fprintf(w, "%%{init: {'flowchart': {'htmlLabels': false}}}%%\n")
	fmt.Fprintf(w, "flowchart LR\n")
	if label != "" {
		fmt.Fprintf(w, "  %%%% %s\n", label)
	}
	if g != nil {
		nodes := append([]GraphNode{}, g.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for _, n := range nodes {
			fmt.Fprintf(w, "  %s[\"%s<br/>(%s)\"]\n", sanitizeMermaidID(n.ID), n.Label, n.Kind)
		}
		for _, e := range g.Edges {
			if e.Label != "" {
				fmt.Fprintf(w, "  %s -- %s --> %s\n", sanitizeMermaidID(e.From), e.Label, sanitizeMermaidID(e.To))
			} else {
				fmt.Fprintf(w, "  %s --> %s\n", sanitizeMermaidID(e.From), sanitizeMermaidID(e.To))
			}
		}
	}
	return nil
}

func sanitizeMermaidID(s string) string {
	r := strings.NewReplacer("/", "_", ".", "_", "-", "_", ":", "_", " ", "_")
	return r.Replace(s)
}

// Note appends an informational note (e.g. a not-yet-implemented marker) to a
// Table. Notes are rendered under tables and embedded in json/yaml output.
func Note(t *Table, format string, args ...interface{}) {
	t.Notes = append(t.Notes, fmt.Sprintf(format, args...))
}

// NYI marks a capability as not-yet-implemented with a consistent prefix.
func NYI(t *Table, what string) {
	Note(t, "ℹ not yet implemented: %s", what)
}
