package model

import (
	"slices"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	"github.com/np-guard/vmware-analyzer/pkg/output"
)

// connMap captures permitted connections between endpoints in the input config
type connMap map[*endpoints.VM]map[*endpoints.VM]*connection.Set

// add func adds a given pair with specified permitted connection
func (c connMap) add(src, dst *endpoints.VM, conn *connection.Set) {
	if _, ok := c[src]; !ok {
		c[src] = map[*endpoints.VM]*connection.Set{}
	}
	c[src][dst] = conn
}

// initPairs adds all possible pairs with allow-all or deny-all, based on initAllow
func (c connMap) initPairs(initAllow bool, vms []*endpoints.VM) {
	for _, src := range vms {
		for _, dst := range vms {
			if src == dst {
				continue
			}
			if initAllow {
				c.add(src, dst, connection.All())
			} else {
				c.add(src, dst, connection.None())
			}
		}
	}
}

// String returns a concatenated lines strings with all VM pairs and their permitted connections.
// If the input vms list is not empty, if returns only connection lines with pairs contained in this list.
// Todo: sunset this:
func (c connMap) String(vms []string) string {
	return c.Graph(vms).Text()
}

// Graph() returns a graph with all VM pairs and their permitted connections.
// If the input vms list is not empty, if returns graph with only pairs contained in this list.
func (c connMap) Graph(vms []string) output.Graph {
	graph := output.NewGraph()
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			if (len(vms) > 0 && slices.Contains(vms, src.Name()) && slices.Contains(vms, dst.Name())) || len(vms) == 0 {
				graph.AddEdge(src,dst, conn.String())
			}
		}
	}
	return graph
}
