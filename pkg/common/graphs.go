/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

const (
	TextFormat = "txt"
	DotFormat  = "dot"
	JsonFormat = "json"
	SvgFormat  = "svg"
)

type node interface {
	Name() string
	Kind() string
}

type Graph interface {
	AddEdge(src, dst node, label string)
	String() string
	JSONString() (string, error)
}

func OutputGraph(g Graph, fileName, format string) (res string, err error) {
	switch format {
	case JsonFormat:
		res, err = g.JSONString()
	case TextFormat:
		res = g.String()
	case DotFormat:
		res = g.String()
	}
	if err != nil {
		return "", err
	}
	if fileName != "" {
		err := WriteToFile(fileName, res)
		if err != nil {
			return "", err
		}
	}
	return res, nil
}


//////////////////////////////////

type edge struct {
	src, dst node
	label    string
}

type EdgesGraph []edge

func NewEdgesGraph() *EdgesGraph {
	return &EdgesGraph{}
}

func (e *edge) string() string {
	str := fmt.Sprintf("src:%s, dst: %s", e.src.Name(), e.dst.Name())
	if e.label != "" {
		str += fmt.Sprintf(" allowedConns: %s", e.label)
	}
	return str
}

func (eg *EdgesGraph) AddEdge(src, dst node, label string) {
	if src == nil || dst == nil {
		return
	}
	*eg = append(*eg, edge{src, dst, label})
}

func (eg *EdgesGraph) strings() []string {
	strs := make([]string, len(*eg))
	for i, e := range *eg {
		strs[i] = e.string()
	}
	return strs

}
func (eg *EdgesGraph) String() string {
	return strings.Join(eg.strings(), "\n")
}
func (eg *EdgesGraph) JSONString() (string, error) {
	toPrint, err := json.MarshalIndent(eg.strings(), "", "    ")
	return string(toPrint), err
}

// ////////////////////////////////////////////////////////////////
type TreeGraph struct {
	root  *treeNode
	nodes map[node]*treeNode
}

func NewTreeGraph() *TreeGraph {
	root := newTreeNode("")
	return &TreeGraph{root: root, nodes: map[node]*treeNode{nil: root}}
}

func (tg *TreeGraph) AddEdge(src, dst node, label string) {
	for _, n := range []node{src, dst} {
		if n != nil {
			if _, ok := tg.nodes[n]; !ok {
				tg.nodes[n] = newTreeNode(n.Name())
			}
		}
	}
	tg.nodes[src].addChild(dst.Kind()+"s", tg.nodes[dst])
}

type treeNodeChildren []*treeNode
type treeNode map[string]interface{}

func newTreeNode(name string) *treeNode {
	tn := treeNode{}
	if name != "" {
		tn["name"] = name
	}
	return &tn
}

func (tn *treeNode) addChild(cType string, c *treeNode) {
	if _, ok := (*tn)[cType]; !ok {
		(*tn)[cType] = treeNodeChildren{}
	}
	(*tn)[cType] = append(((*tn)[cType]).(treeNodeChildren), c)
}

func (tg *TreeGraph) JSONString() (string, error) {
	toPrint, err := json.MarshalIndent(tg.root, "", "    ")
	return string(toPrint), err
}
func (tg *TreeGraph) String() string {
	// todo - implement if needed
	return ""
}

////////////////////////////////////////////////////////////////////////////////

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
	rank          bool
}

func NewDotGraph(rank bool) *DotGraph {
	return &DotGraph{nodes: map[node]*dotNode{}, rank: rank}
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

func (dotGraph *DotGraph) String() string {
	nodeLines := make([]string, len(dotGraph.nodes))
	for i, n := range slices.Collect(maps.Values(dotGraph.nodes)) {
		nodeLines[i] = n.string()
	}
	edgeLines := make([]string, len(dotGraph.edges))
	for i, e := range dotGraph.edges {
		edgeLines[i] = e.string()
	}
	var rankdir, rankString string
	if dotGraph.rank {
		rankdir = "rankdir = \"LR\";"
		rankString = dotGraph.rankString()
	}
	return fmt.Sprintf("digraph{\n%s\n%s\n\n%s\n\n%s\n}\n", rankdir, strings.Join(nodeLines, "\n"), rankString, strings.Join(edgeLines, "\n"))
}

func (dotGraph *DotGraph) JSONString() (string, error) {
	return "", nil
}
