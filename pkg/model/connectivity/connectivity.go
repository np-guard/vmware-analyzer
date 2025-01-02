package connectivity

import (
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// ConnMap captures permitted connections between endpoints in the input config
type ConnMap map[*endpoints.VM]map[*endpoints.VM]*DetailedConnection

// add func adds a given pair with specified permitted connection
func (c ConnMap) Add(src, dst *endpoints.VM, conn *DetailedConnection) {
	if _, ok := c[src]; !ok {
		c[src] = map[*endpoints.VM]*DetailedConnection{}
	}
	c[src][dst] = conn
}

// initPairs adds all possible pairs with allow-all or deny-all, based on initAllow
func (c ConnMap) InitPairs(initAllow bool, vms []*endpoints.VM, vmsFilter []string) {
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
				c.Add(src, dst, NewAllDetailedConnection())
			} else {
				c.Add(src, dst, NewEmptyDetailedConnection())
			}
		}

	}
}

func (c ConnMap) filter(vms []string) ConnMap {
	if len(vms) == 0 {
		return c
	}
	newC := ConnMap{}
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			if slices.Contains(vms, src.Name()) && slices.Contains(vms, dst.Name()) {
				newC.Add(src, dst, conn)
			}
		}
	}
	return newC
}

// connMapEntry captures one entry in ConnMap
type connMapEntry struct {
	Src, Dst *endpoints.VM
	Conn     *DetailedConnection
}

func (c ConnMap) toSlice() (res []connMapEntry) {
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			res = append(res, connMapEntry{src, dst, conn})
		}
	}
	return res
}
