/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
)

type TopologyGraph interface {
	AddEdge(src, dst node, dstType, label string)
}

type nodeType string
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
func (tt *Tree) AddEdge(src, dst node, dstType, label string) {
	for _, n := range []node{src, dst} {
		if n != nil {
			if _, ok := tt.nodes[n]; !ok {
				tt.nodes[n] = newTreeNode(n.Name())
			}
		}
	}
	tt.nodes[src].addChild(dstType+"s", tt.nodes[dst])
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
