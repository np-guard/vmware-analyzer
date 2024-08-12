package model

import (
	"github.com/np-guard/nsx-api-demo/pkg/model/dfw"
	"github.com/np-guard/nsx-api-demo/pkg/model/endpoints"
)

// capture nsx config to analyze
type config struct {
	vms []*endpoints.VM
	fw  *dfw.DFW // currently assuming one DFW only (todo: rename pkg dfw)
}

func (c *config) getConnectivity() connMap {
	res := connMap{}
	for _, src := range c.vms {
		for _, dst := range c.vms {
			if src == dst {
				continue
			}
			conn := c.fw.AnalyzeDFW(src, dst)
			res.add(src, dst, conn)
		}
	}
	return res
}
