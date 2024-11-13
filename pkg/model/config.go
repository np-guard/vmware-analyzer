package model

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

const (
	outputSectionSep = "-------------------------------------------------------------------"
)

// config captures nsx config
type config struct {
	vms                  []*endpoints.VM          // list of all vms
	vmsMap               map[string]*endpoints.VM // map from uid to vm objects
	fw                   *dfw.DFW                 // currently assuming one DFW only (todo: rename pkg dfw)
	analyzedConnectivity connMap                  // the resulting connectivity map from analyzing this configuration
	analysisDone         bool
}

func (c *config) getConnectivity() connMap {
	if !c.analysisDone {
		c.ComputeConnectivity()
	}
	return c.analyzedConnectivity
}

func (c *config) ComputeConnectivity() {
	logging.Debugf("compute connectivity on parsed config")
	res := connMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.initPairs(c.fw.GlobalDefaultAllow(), c.vms)
	// iterate over all vm pairs, get the analysis result per pair
	for _, src := range c.vms {
		for _, dst := range c.vms {
			if src == dst {
				continue
			}
			conn := c.fw.AllowedConnections(src, dst)
			res.add(src, dst, conn)
		}
	}
	c.analyzedConnectivity = res
	c.analysisDone = true
}

// getConfigInfoStr returns string describing the captured configuration content
func (c *config) getConfigInfoStr() string {
	var sb strings.Builder
	sb.WriteString("\n" + outputSectionSep + "\n")
	sb.WriteString("VMs:\n")
	for _, vm := range c.vms {
		sb.WriteString(vm.Name() + "\n")
	}

	sb.WriteString("DFW:\n")
	sb.WriteString(c.fw.String())
	sb.WriteString(c.fw.AllEffectiveRules())
	sb.WriteString("\n" + outputSectionSep + "\n")

	return sb.String()
}
