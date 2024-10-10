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
type Graph interface {
	AddEdge(src, dst node, label string)
}

type graphGenerator interface {
	CreateGraph(g Graph)
}

func OutputGraph(fileName, format string, flat bool, gen graphGenerator) (res string, err error) {
	switch {
	case  format == JsonFormat && flat:
		g := &Edges{}
		gen.CreateGraph(g)
		res, err = g.JSONString()
	case format == JsonFormat && !flat:
		g := NewTree()
		gen.CreateGraph(g)
		res, err = g.JSONString()
	case format == TextFormat:
		g := &Edges{}
		gen.CreateGraph(g)
		res = g.String()
	case format == DotFormat:
		g := NewDotGraph()
		gen.CreateGraph(g)
		res = g.String(flat)
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

type edge struct {
	src, dst node
	label    string
}
type Edges []edge

func (e *edge) string() string{
	str := fmt.Sprintf("src:%s, dst: %s", e.src.Name(), e.dst.Name())
	if e.label != "" {
		str += fmt.Sprintf(" allowedConns: %s", e.label)
	}
	return str
}

func (tt *Edges) AddEdge(src, dst node, label string) {
	if src == nil || dst == nil {
		return
	}
	*tt = append(*tt, edge{src,dst,label})
}
func (tt *Edges) strings()[]string{
	strs := make([]string,len(*tt))
	for i,e := range *tt{
		strs[i] = e.string()
	}
	return strs

}
func (tt *Edges) String() string {
	return strings.Join(tt.strings(), "\n")
}
func (tt *Edges) JSONString() (string, error) {
	toPrint, err := json.MarshalIndent(tt.strings(), "", "    ")
	return string(toPrint), err
}

// ////////////////////////////////////////////////////////////////
type Tree struct {
	root  *treeNode
	nodes map[node]*treeNode
}

type treeNodeChildren []*treeNode
type treeNode map[string]interface{}

func NewTree() *Tree {
	root := newTreeNode("")
	return &Tree{root: root, nodes: map[node]*treeNode{nil: root}}
}

func newTreeNode(name string) *treeNode {
	tn := treeNode{}
	if name != "" {
		tn["name"] = name
	}
	return &tn
}
func (tt *Tree) AddEdge(src, dst node, label string) {
	for _, n := range []node{src, dst} {
		if n != nil {
			if _, ok := tt.nodes[n]; !ok {
				tt.nodes[n] = newTreeNode(n.Name())
			}
		}
	}
	tt.nodes[src].addChild(dst.Kind()+"s", tt.nodes[dst])
}

func (tn *treeNode) addChild(cType string, c *treeNode) {
	if _, ok := (*tn)[cType]; !ok {
		(*tn)[cType] = treeNodeChildren{}
	}
	(*tn)[cType] = append(((*tn)[cType]).(treeNodeChildren), c)
}

func (tt *Tree) JSONString() (string, error) {
	toPrint, err := json.MarshalIndent(tt.root, "", "    ")
	return string(toPrint), err
}
