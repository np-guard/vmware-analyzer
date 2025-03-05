package connectivity

import (
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// ConnMap captures permitted connections between endpoints in the input config
type ConnMap map[topology.Endpoint]map[topology.Endpoint]*DetailedConnection

// Add func adds a given pair with specified permitted connection
func (c ConnMap) Add(src, dst topology.Endpoint, conn *DetailedConnection) {
	if _, ok := c[src]; !ok {
		c[src] = map[topology.Endpoint]*DetailedConnection{}
	}
	c[src][dst] = conn
}

// InitPairs adds all possible pairs with allow-all or deny-all, based on initAllow
func (c ConnMap) InitPairs(initAllow bool, vms, referencedEP []topology.Endpoint, vmsFilter []string) {
	filterFunc := func(ep topology.Endpoint) bool { return len(vmsFilter) > 0 && slices.Contains(vmsFilter, ep.Name()) }
	filteredVMs := slices.DeleteFunc(slices.Clone(vms), filterFunc)
	filteredReferencedEP := slices.DeleteFunc(slices.Clone(referencedEP), filterFunc)
	for _, src := range filteredVMs {
		for _, dst := range filteredReferencedEP {
			if src == dst {
				continue
			}
			if initAllow {
				c.Add(src, dst, NewAllDetailedConnection())
				c.Add(dst, src, NewAllDetailedConnection())
			} else {
				c.Add(src, dst, NewEmptyDetailedConnection())
				c.Add(dst, src, NewEmptyDetailedConnection())
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
	Src, Dst     topology.Endpoint
	DetailedConn *DetailedConnection
}

func (c ConnMap) toSlice() (res []*connMapEntry) {
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			res = append(res, &connMapEntry{src, dst, conn})
		}
	}
	return res
}

func (c ConnMap) getEntryPerEndpoints(srcVM, dstVM string) *connMapEntry {
	entries := c.toSlice()
	for _, entry := range entries {
		if entry.Src.Name() == srcVM && entry.Dst.Name() == dstVM {
			return entry
		}
	}
	logging.Debugf("could not find entry for srcVN,dstVM : %s, %s", srcVM, dstVM)
	return nil
}
