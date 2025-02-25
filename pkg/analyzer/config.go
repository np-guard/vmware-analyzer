package model

import (
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/endpoints"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

type ParsedNSXConfig interface {
	AnalyzedConnectivity() connectivity.ConnMap
	DFW() *dfw.DFW
	DefaultDenyRule() *dfw.FwRule
	VMs() []endpoints.EP
	VMToGroupsMap() map[endpoints.EP][]*collector.Group
}

// config captures nsx config, implements NSXConfig interface
type config struct {
	vms                  []endpoints.EP                      // list of all vms
	externalIPBlocks     []endpoints.EP                      // list of all external blocks
	vmsMap               map[string]endpoints.EP            // map from uid to vm objects
	Fw                   *dfw.DFW                            // currently assuming one DFW only (todo: rename pkg dfw)
	GroupsPerVM          map[endpoints.EP][]*collector.Group // map from vm to its groups
	analyzedConnectivity connectivity.ConnMap                // the resulting connectivity map from analyzing this configuration
	analysisDone         bool
}

func (c *config) AnalyzedConnectivity() connectivity.ConnMap {
	return c.analyzedConnectivity
}
func (c *config) DFW() *dfw.DFW {
	return c.Fw
}
func (c *config) VMs() []endpoints.EP {
	return c.vms
}
func (c *config) EPs() []endpoints.EP {
	return slices.Concat(c.vms, c.externalIPBlocks)
}

func (c *config) VMToGroupsMap() map[endpoints.EP][]*collector.Group {
	return c.GroupsPerVM
}

func (c *config) ComputeConnectivity(vmsFilter []string) {
	logging.Debugf("compute connectivity on parsed config")
	res := connectivity.ConnMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.InitPairs(false, c.EPs(), vmsFilter)
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
		lines = append(lines, vm.InfoStr())
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}

func (c *config) DefaultDenyRule() *dfw.FwRule {
	for _, category := range c.Fw.CategoriesSpecs {
		if category.Category == collector.LastCategory() {
			for _, rule := range category.Rules {
				if rule.IsDenyAll() {
					return rule
				}
			}
		}
	}
	return nil
}
