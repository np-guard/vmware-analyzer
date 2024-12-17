package model

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// connMap captures permitted connections between endpoints in the input config
type connMap map[*endpoints.VM]map[*endpoints.VM]*common.DetailedConnection
type connMapEntry struct {
	src, dst *endpoints.VM
	conn     *common.DetailedConnection
}

// add func adds a given pair with specified permitted connection
func (c connMap) add(src, dst *endpoints.VM, conn *common.DetailedConnection) {
	if _, ok := c[src]; !ok {
		c[src] = map[*endpoints.VM]*common.DetailedConnection{}
	}
	c[src][dst] = conn
}

// initPairs adds all possible pairs with allow-all or deny-all, based on initAllow
func (c connMap) initPairs(initAllow bool, vms []*endpoints.VM, vmsFilter []string) {
	vmsToaAnalyze := map[string]bool{}
	if len(vmsFilter) > 0 {
		for _, vmName := range vmsFilter {
			vmsToaAnalyze[vmName] = true
		}
	}
	for _, src := range vms {
		for _, dst := range vms {
			if src == dst {
				continue
			}
			if len(vmsFilter) > 0 && !(vmsToaAnalyze[src.Name()] && vmsToaAnalyze[dst.Name()]) {
				continue
			}
			if initAllow {
				c.add(src, dst, common.NewAllDetailedConnection())
			} else {
				c.add(src, dst, common.NewEmptyDetailedConnection())
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
		lines[i] = fmt.Sprintf("src:%s, dst: %s, allowedConns: %s", e.src.Name(), e.dst.Name(), e.conn.Conn.String())
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
