package model

import (
	"strings"

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

func (c *config) ComputeConnectivity(vmsFilter []string) {
	logging.Debugf("compute connectivity on parsed config")
	res := connectivity.ConnMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.InitPairs(false, c.vms, vmsFilter)
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

// GetConfigInfoStr returns string describing the captured configuration content
func (c *config) GetConfigInfoStr(color bool) string {
	var sb strings.Builder
	sb.WriteString(common.OutputSectionSep)
	sb.WriteString("VMs:\n")
	sb.WriteString(c.getVMsInfoStr(color))

	// groups
	sb.WriteString(common.OutputSectionSep)
	sb.WriteString("Groups:\n")
	sb.WriteString(c.getVMGroupsStr(color))
	sb.WriteString(common.OutputSectionSep)

	sb.WriteString("DFW:\n")
	sb.WriteString(c.Fw.OriginalRulesStrFormatted(color))
	sb.WriteString(common.ShortSep)
	sb.WriteString(c.Fw.String())
	sb.WriteString(common.ShortSep)
	sb.WriteString(c.Fw.AllEffectiveRules())
	sb.WriteString(common.OutputSectionSep)

	return sb.String()
}

func (c *config) getVMGroupsStr(color bool) string {
	header := []string{"VM", "Groups"}
	lines := [][]string{}
	for vm, groups := range c.GroupsPerVM {
		groupsStr := common.JoinCustomStrFuncSlice(groups, func(g *collector.Group) string { return *g.DisplayName }, common.CommaSpaceSeparator)
		lines = append(lines, []string{vm.Name(), groupsStr})
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}

func (c *config) getVMsInfoStr(color bool) string {
	header := []string{"VM Name", "VM ID", "VM Addresses"}
	lines := [][]string{}
	for _, vm := range c.vms {
		lines = append(lines, []string{vm.Name(), vm.ID(), strings.Join(vm.IPAddresses(), common.CommaSeparator)})
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}

func (c *config) DefaultDenyRule() *dfw.FwRule {
	for _, category := range c.Fw.CategoriesSpecs {
		if category.Category == collector.LastCategory() {
			for _, rule := range category.Rules {
				if rule.Action == dfw.ActionDeny &&
					rule.IsAllSrcGroups &&
					rule.IsAllDstGroups {
					return rule
				}
			}
		}
	}
	return nil
}
