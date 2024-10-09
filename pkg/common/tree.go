/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
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

func OutputGraph(fileName, format string, dotRank bool, gen graphGenerator) (res string, err error) {
	switch format {
	case JsonFormat:
		g := NewTree()
		gen.CreateGraph(g)
		res, err = g.JSONString()
	case TextFormat:
		g := NewTree()
		gen.CreateGraph(g)
		res, err = g.JSONString()
	case DotFormat:
		g := NewDotGraph()
		gen.CreateGraph(g)
		res = g.String(dotRank)
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
