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

func (g *graph) Dot() string {
	dotNode := map[node]int{}
	for _, e := range *g {
		if _, ok := dotNode[e.src]; !ok {
			dotNode[e.src] = len(dotNode)
		}
		if _, ok := dotNode[e.dst]; !ok {
			dotNode[e.dst] = len(dotNode)
		}
	}
	nodeLines := make([]string, len(dotNode))
	for n, nID := range dotNode {
		nodeLines[nID] = fmt.Sprintf("node_%d_[label=%q]", nID, n.Name())
	}
	edgeLines := make([]string, len(*g))
	for i, e := range *g {
		edgeLines[i] = fmt.Sprintf("node_%d_ -> node_%d_", dotNode[e.src], dotNode[e.dst])
	}
	return fmt.Sprintf("diagram{\n%s\n\n%s\n}\n", strings.Join(nodeLines, "\n"), strings.Join(edgeLines, "\n"))
}

// func (g *graph) Dot(fileName string, format graphviz.Format) error {
// 	gw := graphviz.New()
// 	dotGraph, err := gw.Graph()
// 	if err != nil {
// 		return err
// 	}
// 	defer func() error {
// 		if err := dotGraph.Close(); err != nil {
// 			return err
// 		}
// 		gw.Close()
// 		return nil
// 	}()
// 	dotNode := map[node]*cgraph.Node{}
// 	for _, e := range *g {
// 		if _, ok := dotNode[e.src]; !ok {
// 			dotNode[e.src], err = dotGraph.CreateNode(e.src.Name())
// 			if err != nil {
// 				return err
// 			}
// 		}
// 		if _, ok := dotNode[e.src]; !ok {
// 			dotNode[e.dst], err = dotGraph.CreateNode(e.dst.Name())
// 			if err != nil {
// 				return err
// 			}
// 		}
// 		dotEdge, err := dotGraph.CreateEdge(e.label, dotNode[e.src], dotNode[e.dst])
// 		if err != nil {
// 			return err
// 		}
// 		dotEdge.SetLabel(e.label)
// 	}
// 	var buf bytes.Buffer
// 	if err := gw.Render(dotGraph, format, &buf); err != nil {
// 		return err
// 	}
// 	return nil
// }
