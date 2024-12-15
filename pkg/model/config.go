package model

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// config captures nsx config
type config struct {
	Vms                  []*endpoints.VM          // list of all Vms
	vmsMap               map[string]*endpoints.VM // map from uid to vm objects
	Fw                   *dfw.DFW                 // currently assuming one DFW only (todo: rename pkg dfw)
	analyzedConnectivity connMap                  // the resulting connectivity map from analyzing this configuration
	analysisDone         bool
}

func (c *config) getConnectivity() connMap {
	if !c.analysisDone {
		c.ComputeConnectivity(nil)
	}
	return c.analyzedConnectivity
}

func (c *config) ComputeConnectivity(vmsFilter []string) {
	logging.Debugf("compute connectivity on parsed config")
	res := connMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.initPairs(c.Fw.GlobalDefaultAllow(), c.Vms, vmsFilter)
	// iterate over all vm pairs in the initialized map at res, get the analysis result per pair
	for src, srcMap := range res {
		for dst := range srcMap {
			if src == dst {
				continue
			}
			conn := c.Fw.AllowedConnections(src, dst)
			res.add(src, dst, conn)
		}
	}
	c.analyzedConnectivity = res
	c.analysisDone = true
}

// GetConfigInfoStr returns string describing the captured configuration content
func (c *config) GetConfigInfoStr() string {
	var sb strings.Builder
	sb.WriteString(common.OutputSectionSep)
	sb.WriteString("VMs:\n")
	for _, vm := range c.Vms {
		sb.WriteString(vm.Name() + "\n")
	}
	sb.WriteString(common.OutputSectionSep)

	sb.WriteString("DFW:\n")
	sb.WriteString(c.Fw.OriginalRulesStrFormatted())
	sb.WriteString(common.ShortSep)
	sb.WriteString(c.Fw.String())
	sb.WriteString(common.ShortSep)
	sb.WriteString(c.Fw.AllEffectiveRules())
	sb.WriteString(common.OutputSectionSep)

	return sb.String()
}
