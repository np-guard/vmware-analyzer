/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

type nodeID int
type dotNode struct {
	node
	ID nodeID
}

func (n *dotNode) string() string {
	return fmt.Sprintf("node_%d_[shape=box, label=%q, tooltip=%q]", n.ID, n.Kind()+":"+n.Name(), n.Name())
}

type dotEdge struct {
	src, dst *dotNode
	label    string
}

func (e *dotEdge) string() string {
	return fmt.Sprintf("node_%d_ -> node_%d_[label=%q, tooltip=%q, labeltooltip=%q]",
		e.src.ID, e.dst.ID, e.label, e.label, e.label)
}

type DotGraph struct {
	edges         []*dotEdge
	nodeIDcounter nodeID
	nodes         map[node]*dotNode
}

func NewDotGraph() *DotGraph {
	return &DotGraph{nodes: map[node]*dotNode{}}
}

func (dotGraph *DotGraph) AddEdge(src, dst node, label string) {
	for _, n := range []node{src, dst} {
		if _, ok := dotGraph.nodes[n]; n != nil && !ok {
			dotGraph.nodes[n] = &dotNode{n, dotGraph.nodeIDcounter}
			dotGraph.nodeIDcounter++
		}
	}
	if src != nil && dst != nil {
		dotGraph.edges = append(dotGraph.edges, &dotEdge{dotGraph.nodes[src], dotGraph.nodes[dst], label})
	}
}
func (dotGraph *DotGraph) rankString() string {
	nodesByKinds := map[string][]*dotNode{}
	for n, dn := range dotGraph.nodes {
		nodesByKinds[n.Kind()] = append(nodesByKinds[n.Kind()], dn)
	}
	ranks := make([]string, len(nodesByKinds))
	for ri, nodes := range slices.Collect(maps.Values(nodesByKinds)) {
		nodesIds := make([]string, len(nodes))
		for ni, n := range nodes {
			nodesIds[ni] = fmt.Sprintf("node_%d_", n.ID)
		}
		ranks[ri] = fmt.Sprintf("{rank=same; %s}", strings.Join(nodesIds, " "))
	}
	return strings.Join(ranks, "\n")
}

func (dotGraph *DotGraph) String(rank bool) string {
	nodeLines := make([]string, len(dotGraph.nodes))
	for i, n := range slices.Collect(maps.Values(dotGraph.nodes)) {
		nodeLines[i] = n.string()
	}
	edgeLines := make([]string, len(dotGraph.edges))
	for i, e := range dotGraph.edges {
		edgeLines[i] = e.string()
	}
	var rankdir, rankString string
	if rank {
		rankdir = "rankdir = \"LR\";"
		rankString = dotGraph.rankString()
	}
	return fmt.Sprintf("digraph{\n%s\n%s\n\n%s\n\n%s\n}\n", rankdir, strings.Join(nodeLines, "\n"), rankString, strings.Join(edgeLines, "\n"))
}
