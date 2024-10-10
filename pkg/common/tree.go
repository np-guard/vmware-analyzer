/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"fmt"
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
type edge struct {
	src, dst node
	label    string
}

type Graph interface {
	AddEdge(src, dst node, label string)
	String() string
	JSONString() (string, error)
}

//////////////////////////////////

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

//////////////////////////////////////////////////////////////////////////////////

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
