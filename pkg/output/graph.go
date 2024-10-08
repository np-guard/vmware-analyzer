/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package output

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

type node interface {
	Name() string
}
type edge struct {
	src, dst node
	label    string
}
type graph []edge

// /////////////////////////
type Graph interface {
	AddEdge(src, dst node, label string)
	Text() string
	Dot() string
}

func NewGraph() Graph {
	return &graph{}
}
func (g *graph) AddEdge(src, dst node, label string) {
	*g = append(*g, edge{src, dst, label})
}

func (g *graph) Text() string {
	lines := make([]string, len(*g))
	for i, e := range *g {
		lines[i] = fmt.Sprintf("src:%s, dst: %s, allowedConns: %s", e.src.Name(), e.dst.Name(), e.label)
	}
	return strings.Join(lines, "\n")
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

func (g *graph) dotGraph() *dotGraph {
	nodes := map[node]dotNode{}
	dotEdges := map[dotEdge]bool{}
	var nodeIDcounter nodeID
	for _, e := range *g {
		for _, n := range []node{e.src, e.dst} {
			if _, ok := nodes[n]; !ok {
				nodes[n] = dotNode{n, nodeIDcounter}
				nodeIDcounter++
			}
		}
		dotE := dotEdge{nodes[e.src], nodes[e.dst],e.label, true}
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

func (g *graph) Dot() string {
	dotGraph := g.dotGraph()
	nodeLines := make([]string, len(dotGraph.nodes))
	for i, n := range dotGraph.nodes {
		nodeLines[i] = fmt.Sprintf("node_%d_[label=%q, tooltip=%q]", n.ID, n.Name(), n.Name())
	}
	edgeLines := make([]string, len(dotGraph.edges))
	for i,e := range dotGraph.edges {
		dotDir := map[bool]string{false:"", true:" ,dir=none"}
		edgeLines[i] = fmt.Sprintf("node_%d_ -> node_%d_[label=%q, tooltip=%q %s]", e.src.ID, e.dst.ID, e.label, e.label, dotDir[e.directed])
	}
	return fmt.Sprintf("diagram{\n%s\n\n%s\n}\n", strings.Join(nodeLines, "\n"), strings.Join(edgeLines, "\n"))
}
