/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
)

const (
	TextFormat = "txt"
	DotFormat  = "dot"
	JSONFormat = "json"
	SvgFormat  = "svg"
)

type node interface {
	Name() string
	Kind() string
}
type label interface {
	String() string
}

type Graph interface {
	AddEdge(src, dst node, label label)
	String() string
	JSONString() (string, error)
}

func OutputGraph(g Graph, fileName, format string) (res string, err error) {
	switch format {
	case JSONFormat:
		res, err = g.JSONString()
	case TextFormat:
		res = g.String()
	case DotFormat, SvgFormat:
		res = g.String()
	}
	if err != nil {
		return "", err
	}
	if format == SvgFormat {
		dotFile := fileName + ".tmp.dot"
		err = WriteToFile(dotFile, res)
		if err != nil {
			return "", err
		}
		bts, err := exec.Command("dot", "-T"+format, dotFile).Output() //nolint:gosec // running the dot command
		if err != nil {
			return "", err
		}
		if err := os.Remove(dotFile); err != nil {
			return "", err
		}
		res = string(bts)
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
	label    label
}

type EdgesGraph struct {
	edges  []edge
	header string
}

func NewEdgesGraph(header string) *EdgesGraph {
	return &EdgesGraph{header: header}
}

func (e *edge) string() string {
	str := fmt.Sprintf("%s => %s", e.src.Name(), e.dst.Name())
	if e.label != nil {
		str += fmt.Sprintf(": %s", e.label.String())
	}
	return str
}

func (eg *EdgesGraph) AddEdge(src, dst node, label label) {
	if src == nil || dst == nil {
		return
	}
	eg.edges = append(eg.edges, edge{src, dst, label})
}

func (eg *EdgesGraph) String() string {
	strs := make([]string, len(eg.edges))
	for i, e := range eg.edges {
		strs[i] = e.string()
	}
	slices.Sort(strs)
	return fmt.Sprintf("%s:\n%s", eg.header, strings.Join(strs, "\n"))
}

func (eg *EdgesGraph) JSONString() (string, error) {
	asMaps := make([]map[string]string, len(eg.edges))
	for i, e := range eg.edges {
		asMaps[i] = map[string]string{"src": e.src.Name(), "dst": e.dst.Name()}
		if e.label != nil {
			asMaps[i]["conn"] = e.label.String()
		}
	}
	return indentMarshal(asMaps)
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

func (tg *TreeGraph) AddEdge(src, dst node, label label) {
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
	return indentMarshal(tg.root)
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
	return fmt.Sprintf("node_%d_[shape=box, label=%q, tooltip=%q fontcolor=darkgreen color=darkred]",
		n.ID, n.Kind()+":"+n.Name(), n.Name())
}

type dotEdge struct {
	src, dst *dotNode
	label    label
}

func (e *dotEdge) string(labelAtToolTip bool) string {
	s := fmt.Sprintf("node_%d_ -> node_%d_", e.src.ID, e.dst.ID)
	if e.label != nil {
		label := e.label.String()
		if labelAtToolTip{
			label = "*"
		}
		s += fmt.Sprintf("[label=%q, tooltip=%q, labeltooltip=%q fontcolor=purple color=darkblue]",
			label, e.label.String(), e.label.String())
	}
	return s
}

type DotGraph struct {
	edges                []*dotEdge
	nodeIDcounter        nodeID
	nodes                map[node]*dotNode
	rank, labelAtToolTip bool
}

func NewDotGraph(rank, labelAtToolTip bool) *DotGraph {
	return &DotGraph{nodes: map[node]*dotNode{}, rank: rank, labelAtToolTip: labelAtToolTip}
}

func (dotGraph *DotGraph) AddEdge(src, dst node, label label) {
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
		edgeLines[i] = e.string(dotGraph.labelAtToolTip)
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

// //////////////////////////////////////////////////////////////////////////////////////
func indentMarshal(v any) (string, error) {
	toPrint, err := json.MarshalIndent(v, "", "    ")
	return string(toPrint), err
}
