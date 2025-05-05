/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
)

type node interface {
	Name() string
	Kind() string
}
type label interface {
	String() string
}

type labelImpl struct {
	value string
}

func (l *labelImpl) String() string {
	return l.value
}

func LabelFromString(value string) label {
	return &labelImpl{value: value}
}

// Graph interface is implemented by:
// EdgesGraph (for text output)
// DotGraph (for dot/svg output)
// TreeGraph (for json output)
type Graph interface {
	AddEdge(src, dst node, label label)
	String() string
	JSONString() (string, error)
}

func OutputGraph(g Graph, fileName string, format OutFormat) (res string, err error) {
	switch format {
	case JSONFormat:
		res, err = g.JSONString()
	case TextFormat:
		res = g.String()
	case DotFormat, SVGFormat:
		res = g.String()
	}
	if err != nil {
		return "", err
	}
	if format == SVGFormat {
		dotFile := fileName + ".tmp.dot"
		err = WriteToFile(dotFile, res)
		if err != nil {
			return "", err
		}
		bts, err := exec.Command("dot", "-T"+format.String(), dotFile).Output() //nolint:gosec // running the dot command
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
	edges                 []edge
	header                string
	tableHeaderComponents []string
	color                 bool
}

func NewEdgesGraph(header string, tableHeaderComponents []string, color bool) *EdgesGraph {
	return &EdgesGraph{header: header, tableHeaderComponents: tableHeaderComponents, color: color}
}

func (e *edge) tableStringComponents() []string {
	labelStr := ""
	if e.label != nil {
		labelStr = e.label.String()
	}
	if e.src == nil || e.dst == nil {
		return []string{}
	}
	return []string{e.src.Name(), e.dst.Name(), labelStr}
}

//nolint: gocritic // keep  commented-out code for now
/*func (e *edge) string() string {
	str := fmt.Sprintf("%s => %s", e.src.Name(), e.dst.Name())
	if e.label != nil {
		str += fmt.Sprintf(": %s", e.label.String())
	}
	return str
}*/

func (eg *EdgesGraph) AddEdge(src, dst node, label label) {
	if src == nil || dst == nil {
		return
	}
	eg.edges = append(eg.edges, edge{src, dst, label})
}

func (eg *EdgesGraph) String() string {
	//nolint: gocritic // keep  commented-out code for now
	/*edgesStr := SortedJoinCustomStrFuncSlice(eg.edges, func(e edge) string { return e.string() }, "\n")
	return fmt.Sprintf("%s:\n%s", eg.header, edgesStr)*/

	lines := [][]string{}
	for _, e := range eg.edges {
		lines = append(lines, e.tableStringComponents())
	}
	return eg.header + NewLine + GenerateTableString(eg.tableHeaderComponents, lines, &TableOptions{SortLines: true, Colors: eg.color})
}

func (eg *EdgesGraph) JSONString() (string, error) {
	asMaps := make([]map[string]string, len(eg.edges))
	for i, e := range eg.edges {
		asMaps[i] = map[string]string{"src": e.src.Name(), "dst": e.dst.Name()}
		if e.label != nil {
			asMaps[i]["conn"] = e.label.String()
		}
	}
	return MarshalJSON(asMaps)
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
	return MarshalJSON(tg.root)
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

func (e *dotEdge) string() string {
	s := fmt.Sprintf("node_%d_ -> node_%d_", e.src.ID, e.dst.ID)
	if e.label != nil {
		s += fmt.Sprintf("[label=%q, tooltip=%q, labeltooltip=%q fontcolor=purple color=darkblue]",
			e.label.String(), e.label.String(), e.label.String())
	}
	return s
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
	return JoinCustomStrFuncSlice(slices.Collect(maps.Values(nodesByKinds)),
		func(nodesList []*dotNode) string {
			nodeIdsStr := JoinCustomStrFuncSlice(nodesList, func(n *dotNode) string { return fmt.Sprintf("node_%d_", n.ID) }, " ")
			return fmt.Sprintf("{rank=same; %s}", nodeIdsStr)
		}, "\n")
}

func (dotGraph *DotGraph) String() string {
	nodeLines := JoinCustomStrFuncSlice(slices.Collect(maps.Values(dotGraph.nodes)), func(n *dotNode) string { return n.string() }, "\n")
	edgeLines := JoinCustomStrFuncSlice(dotGraph.edges, func(e *dotEdge) string { return e.string() }, "\n")
	var rankdir, rankString string
	if dotGraph.rank {
		rankdir = "rankdir = \"LR\";"
		rankString = dotGraph.rankString()
	}
	return fmt.Sprintf("digraph{\n%s\n%s\n\n%s\n\n%s\n}\n", rankdir, nodeLines, rankString, edgeLines)
}

func (dotGraph *DotGraph) JSONString() (string, error) {
	return "", nil
}
