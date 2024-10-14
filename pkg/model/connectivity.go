package model

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// connMap captures permitted connections between endpoints in the input config
type connMap map[*endpoints.VM]map[*endpoints.VM]*netset.TransportSet
type connMapEntry struct {
	src, dst *endpoints.VM
	conn     *netset.TransportSet
}

// add func adds a given pair with specified permitted connection
func (c connMap) add(src, dst *endpoints.VM, conn *netset.TransportSet) {
	if _, ok := c[src]; !ok {
		c[src] = map[*endpoints.VM]*netset.TransportSet{}
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
				c.add(src, dst, netset.AllTransports())
			} else {
				c.add(src, dst, netset.NoTransports())
			}
		}
	}
}

// String returns a concatenated lines strings with all VM pairs and their permitted connections.
// If the input vms list is not empty, if returns only connection lines with pairs contained in this list.
// Todo: sunset this:
func (c connMap) String() string {
	asSlice := c.toSlice()
	lines := make([]string, len(asSlice))
	for i, e := range asSlice {
		lines[i] = fmt.Sprintf("src:%s, dst: %s, allowedConns: %s", e.src.Name(), e.dst.Name(), e.conn.String())
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

func (c connMap) Filter(vms []string) connMap {
	if len(vms) == 0 {
		return c
	}
	newC := connMap{}
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			if slices.Contains(vms, src.Name()) && slices.Contains(vms, dst.Name()) {
				newC.add(src, dst, conn)
			}
		}
	}
	return newC
}

func (c connMap) toSlice() (res []connMapEntry) {
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			res = append(res, connMapEntry{src, dst, conn})
		}
	}
	return res
}
