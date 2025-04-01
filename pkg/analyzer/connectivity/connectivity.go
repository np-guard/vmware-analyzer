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

// InitPairs adds all possible pairs from/to endpoints1 to/from endpoints2, with allow-all or deny-all, based on initAllow
func (c ConnMap) InitPairs(initAllow bool, endpoints1, endpoints2 []topology.Endpoint, vmsFilter []string) {
	filterFunc := func(ep topology.Endpoint) bool { return len(vmsFilter) > 0 && !slices.Contains(vmsFilter, ep.Name()) }
	endpoints1 = slices.DeleteFunc(slices.Clone(endpoints1), filterFunc)
	endpoints2 = slices.DeleteFunc(slices.Clone(endpoints2), filterFunc)
	for _, src := range endpoints1 {
		for _, dst := range endpoints2 {
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

// this method is for testing only. grouping the external, to compare connectivities
// assuming there is no connection with both src and dst external 
func (c ConnMap) GroupExternalEP() ConnMap {
	unionExternalEP := func(e1, e2 topology.Endpoint) topology.Endpoint {
		return topology.NewExternalIP(
			e1.(*topology.ExternalIP).Block.Union(
				e2.(*topology.ExternalIP).Block))
	}
	entries := map[string]*connMapEntry{}
	for _, entry := range c.toSlice() {
		src, dst := entry.Src, entry.Dst
		var key string
		conn := entry.DetailedConn.Conn
		switch {
		case !entry.Src.IsExternal() && !entry.Dst.IsExternal():
			key = entry.Src.ID() + entry.Dst.ID()
		case entry.Src.IsExternal():
			key = "EX_" + entry.Dst.ID() + entry.DetailedConn.Conn.String()
			if oldEntry, ok := entries[key]; ok {
				src = unionExternalEP(src, oldEntry.Src)
			}
		case entry.Dst.IsExternal():
			key = entry.Src.ID() + "_EX" + entry.DetailedConn.Conn.String()
			if oldEntry, ok := entries[key]; ok {
				dst = unionExternalEP(dst, oldEntry.Dst)
			}
		}
		entries[key] = &connMapEntry{src, dst, &DetailedConnection{Conn: conn}}
	}
	res := ConnMap{}
	for _, entry := range entries {
		res.Add(entry.Src, entry.Dst, entry.DetailedConn)
	}
	return res
}
