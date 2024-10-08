package model

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

const (
	TextFormat = "txt"
	DotFormat  = "dot"
)

type OutputParameters struct {
	Format   string
	FileName string
	VMs      []string
}

func (c *config) Output(args OutputParameters) string {
	filteredConn := c.analyzedConnectivity.Filter(args.VMs)

	switch args.Format {
	case TextFormat:
		return filteredConn.String()
	case DotFormat:
		return createDotGraph(filteredConn.toSlice()).toDotString()
	}
	return ""
}


/////////////////////////////////////////////////////////////////////
type node interface {
	Name() string
}
type nodeID int
type dotNode struct {
	node
	ID nodeID
}
type dotEdge struct {
	src, dst dotNode
	label    string
	directed bool
}
type dotGraph struct {
	nodes []dotNode
	edges []dotEdge
}

func createDotGraph(filteredConn []connMapEntry) *dotGraph {
	nodes := map[node]dotNode{}
	dotEdges := map[dotEdge]bool{}
	var nodeIDcounter nodeID
	for _, e := range filteredConn {
		for _, n := range []node{e.src, e.dst} {
			if _, ok := nodes[n]; !ok {
				nodes[n] = dotNode{n, nodeIDcounter}
				nodeIDcounter++
			}
		}
		dotE := dotEdge{nodes[e.src], nodes[e.dst],e.conn.String(), true}
		revDotE := dotE
		revDotE.src, revDotE.dst = revDotE.dst, revDotE.src
		undirDotE := dotE
		undirRevDotE := revDotE
		undirDotE.directed = false
		undirRevDotE.directed = false
		switch {
		case dotEdges[dotE] || dotEdges[undirDotE] || dotEdges[undirRevDotE]:
		case dotEdges[revDotE]:
			delete(dotEdges, revDotE)
			dotEdges[undirDotE] = true
		default:
			dotEdges[dotE] = true
		}
	}
	return &dotGraph{slices.Collect(maps.Values(nodes)), slices.Collect(maps.Keys(dotEdges))}
}

func (dotGraph *dotGraph)toDotString() string {
	nodeLines := make([]string, len(dotGraph.nodes))
	for i, n := range dotGraph.nodes {
		nodeLines[i] = fmt.Sprintf("node_%d_[shape=box, label=%q, tooltip=%q]", n.ID, n.Name(), n.Name())
	}
	edgeLines := make([]string, len(dotGraph.edges))
	for i,e := range dotGraph.edges {
		dotDir := map[bool]string{false:", dir=both", true:""}
		edgeLines[i] = fmt.Sprintf("node_%d_ -> node_%d_[label=%q, tooltip=%q labeltooltip=%q %s]", e.src.ID, e.dst.ID, e.label, e.label, e.label, dotDir[e.directed])
	}
	return fmt.Sprintf("digraph{\n%s\n\n%s\n}\n", strings.Join(nodeLines, "\n"), strings.Join(edgeLines, "\n"))
}
