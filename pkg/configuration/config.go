package configuration

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/endpoints"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

type ParsedNSXConfig interface {
	AnalyzedConnectivity() connectivity.ConnMap
	DFW() *dfw.DFW
	DefaultDenyRule() *dfw.FwRule
	VMs() []endpoints.EP
	VMToGroupsMap() map[endpoints.EP][]*collector.Group
	GetGroups() []*collector.Group
}

// Config captures nsx Config, implements NSXConfig interface
type Config struct {
	Vms         []endpoints.EP                      // list of all Vms
	VmsMap      map[string]endpoints.EP             // map from uid to vm objects
	Fw          *dfw.DFW                            // currently assuming one DFW only (todo: rename pkg dfw)
	Groups      []*collector.Group                  // list of all groups (also these with no Vms)
	GroupsPerVM map[endpoints.EP][]*collector.Group // map from vm to its groups
	// todo: does not belong here https://github.com/np-guard/vmware-analyzer/issues/280
	Connectivity connectivity.ConnMap // the resulting connectivity map from analyzing this configuration
	AnalysisDone bool
}

func (c *Config) AnalyzedConnectivity() connectivity.ConnMap {
	return c.Connectivity
}
func (c *Config) DFW() *dfw.DFW {
	return c.Fw
}
func (c *Config) VMs() []endpoints.EP {
	return c.Vms
}
func (c *Config) VMToGroupsMap() map[endpoints.EP][]*collector.Group {
	return c.GroupsPerVM
}
func (c *Config) GetGroups() []*collector.Group {
	return c.Groups
}

func (c *Config) ComputeConnectivity(vmsFilter []string) {
	logging.Debugf("compute connectivity on parsed config")
	res := connectivity.ConnMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.InitPairs(false, c.Vms, vmsFilter)
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
	c.Connectivity = res
	c.AnalysisDone = true
}

// GetConfigInfoStr returns string describing the captured configuration content
func (c *Config) GetConfigInfoStr(color bool) string {
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

func (c *Config) getVMGroupsStr(color bool) string {
	header := []string{"VM", "Groups"}
	lines := [][]string{}
	for vm, groups := range c.GroupsPerVM {
		groupsStr := common.JoinCustomStrFuncSlice(groups, func(g *collector.Group) string { return *g.DisplayName }, common.CommaSpaceSeparator)
		lines = append(lines, []string{vm.Name(), groupsStr})
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}

func (c *Config) getVMsInfoStr(color bool) string {
	header := []string{"VM Name", "VM ID", "VM Addresses"}
	lines := [][]string{}
	for _, vm := range c.Vms {
		lines = append(lines, vm.InfoStr())
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}

func (c *Config) DefaultDenyRule() *dfw.FwRule {
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
