package model

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
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

// string returns a concatenated lines strings with all pairs and their permitted connections
func (c connMap) string() string {
	lines := []string{}
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			lines = append(lines, fmt.Sprintf("src:%s, dst: %s, allowedConns: %s", src.Name(), dst.Name(), conn.String()))
		}
	}
	return strings.Join(lines, "\n")
}
