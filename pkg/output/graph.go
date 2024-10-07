/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package output

import (
	"fmt"
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

///////////////////////////
type Graph interface{
	AddEdge(src, dst node, label string)
	Text() string
}
func NewGraph() Graph {
	return &graph{}
}
func (g *graph) AddEdge(src, dst node, label string) {
	*g = append(*g, edge{src, dst, label})
}

func (g *graph) Text() string{
	lines := make([]string, len(*g))
	for i,e := range *g{
		lines[i]= fmt.Sprintf("src:%s, dst: %s, allowedConns: %s", e.src.Name(), e.dst.Name(), e.label)
	} 
	return strings.Join(lines, "\n")
}
