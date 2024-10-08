package model

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/common"
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

func (c *config) output(params OutputParameters) (res string, err error) {
	filteredConn := c.analyzedConnectivity.Filter(params.VMs)

	switch params.Format {
	case TextFormat:
		res = filteredConn.String()
	case DotFormat:
		res = createDotGraph(filteredConn.toSlice()).string()
	}
	if params.FileName != "" {
		err := common.WriteToFile(params.FileName, res)
		if err != nil {
			return "", err
		}
	}
	return res, nil
}

// ///////////////////////////////////////////////////////////////////
type node interface {
	Name() string
}
type nodeID int
type dotNode struct {
	node
	ID nodeID
}

func (n *dotNode) string() string {
	return fmt.Sprintf("node_%d_[shape=box, label=%q, tooltip=%q]", n.ID, n.Name(), n.Name())
}

type dotEdge struct {
	src, dst dotNode
	label    string
}

func (e *dotEdge) string() string {
	return fmt.Sprintf("node_%d_ -> node_%d_[label=%q, tooltip=%q labeltooltip=%q]",
		e.src.ID, e.dst.ID, e.label, e.label, e.label)
}

type dotGraph struct {
	nodes []dotNode
	edges []dotEdge
}

func createDotGraph(conns []connMapEntry) *dotGraph {
	nodes := map[node]dotNode{}
	dotEdges := make([]dotEdge, len(conns))
	var nodeIDcounter nodeID
	for i, e := range conns {
		for _, n := range []node{e.src, e.dst} {
			if _, ok := nodes[n]; !ok {
				nodes[n] = dotNode{n, nodeIDcounter}
				nodeIDcounter++
			}
		}
		dotEdges[i] = dotEdge{nodes[e.src], nodes[e.dst], e.conn.String()}
	}
	return &dotGraph{slices.Collect(maps.Values(nodes)), dotEdges}
}

func (dotGraph *dotGraph) string() string {
	nodeLines := make([]string, len(dotGraph.nodes))
	for i, n := range dotGraph.nodes {
		nodeLines[i] = n.string()
	}
	edgeLines := make([]string, len(dotGraph.edges))
	for i, e := range dotGraph.edges {
		edgeLines[i] = e.string()
	}
	return fmt.Sprintf("digraph{\n%s\n\n%s\n}\n", strings.Join(nodeLines, "\n"), strings.Join(edgeLines, "\n"))
}
