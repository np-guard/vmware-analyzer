package model

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// config captures nsx config
type config struct {
	vms                  []*endpoints.VM                      // list of all vms
	vmsMap               map[string]*endpoints.VM             // map from uid to vm objects
	Fw                   *dfw.DFW                             // currently assuming one DFW only (todo: rename pkg dfw)
	GroupsPerVM          map[*endpoints.VM][]*collector.Group // map from vm to its groups
	analyzedConnectivity connectivity.ConnMap                 // the resulting connectivity map from analyzing this configuration
	analysisDone         bool
}

func (c *config) getConnectivity() connectivity.ConnMap {
	if !c.analysisDone {
		c.ComputeConnectivity(nil)
	}
	return c.analyzedConnectivity
}

func (c *config) ComputeConnectivity(vmsFilter []string) {
	logging.Debugf("compute connectivity on parsed config")
	res := connectivity.ConnMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.InitPairs(c.Fw.GlobalDefaultAllow(), c.vms, vmsFilter)
	// iterate over all vm pairs in the initialized map at res, get the analysis result per pair
	for src, srcMap := range res {
		for dst := range srcMap {
			if src == dst {
				continue
			}
			conn := c.Fw.AllowedConnections(src, dst)
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
	sb.WriteString(c.getVMsInfoStr())

	// groups
	sb.WriteString(common.OutputSectionSep)
	sb.WriteString("Groups:\n")
	sb.WriteString(c.getVMGroupsStr())
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

func (c *config) getVMGroupsStr() string {
	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 1, 1, 1, ' ', tabwriter.Debug)
	fmt.Fprintln(writer, "VM"+"\t"+"Groups")
	for vm, groups := range c.GroupsPerVM {
		groupsStr := common.JoinCustomStrFuncSlice(groups, func(g *collector.Group) string { return *g.DisplayName }, common.CommaSpaceSeparator)
		line := vm.Name() + "\t" + groupsStr
		fmt.Fprintln(writer, line)
	}
	writer.Flush()
	return builder.String()
}

func (c *config) getVMsInfoStr() string {
	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 1, 1, 1, ' ', tabwriter.Debug)
	fmt.Fprintln(writer, "VM name"+"\t"+"VM ID"+"\t"+"VM IP Addresses")
	for _, vm := range c.vms {
		vmStrLine := vm.Name() + "\t" + vm.ID() + "\t" + strings.Join(vm.IPAddresses(), common.CommaSeparator)
		fmt.Fprintln(writer, vmStrLine)
	}
	writer.Flush()
	return builder.String()

}
