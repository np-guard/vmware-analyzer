package model

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/conns"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// config captures nsx config
type config struct {
	vms                  []*endpoints.VM          // list of all vms
	vmsMap               map[string]*endpoints.VM // map from uid to vm objects
	fw                   *dfw.DFW                 // currently assuming one DFW only (todo: rename pkg dfw)
	analyzedConnectivity conns.ConnMap            // the resulting connectivity map from analyzing this configuration
	analysisDone         bool
}

func (c *config) getConnectivity() conns.ConnMap {
	if !c.analysisDone {
		c.ComputeConnectivity(nil)
	}
	return c.analyzedConnectivity
}

func (c *config) ComputeConnectivity(vmsFilter []string) {
	logging.Debugf("compute connectivity on parsed config")
	res := conns.ConnMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.InitPairs(c.fw.GlobalDefaultAllow(), c.vms, vmsFilter)
	// iterate over all vm pairs in the initialized map at res, get the analysis result per pair
	for src, srcMap := range res {
		for dst := range srcMap {
			if src == dst {
				continue
			}
			conn := c.fw.AllowedConnections(src, dst)
			res.Add(src, dst, conn)
		}
	}
	c.analyzedConnectivity = res
	c.analysisDone = true
}

// getConfigInfoStr returns string describing the captured configuration content
func (c *config) getConfigInfoStr() string {
	var sb strings.Builder
	sb.WriteString(common.OutputSectionSep)
	sb.WriteString("VMs:\n")
	for _, vm := range c.vms {
		sb.WriteString(vm.Name() + "\n")
	}
	sb.WriteString(common.OutputSectionSep)

	sb.WriteString("DFW:\n")
	sb.WriteString(c.fw.OriginalRulesStrFormatted())
	sb.WriteString(common.ShortSep)
	sb.WriteString(c.fw.String())
	sb.WriteString(common.ShortSep)
	sb.WriteString(c.fw.AllEffectiveRules())
	sb.WriteString(common.OutputSectionSep)

	return sb.String()
}
