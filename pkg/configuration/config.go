package configuration

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"

	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

type ParsedNSXConfig interface {
	DFW() *dfw.DFW
	DefaultDenyRule() *dfw.FwRule
	VMs() []topology.Endpoint
	VMToGroupsMap() map[topology.Endpoint][]*collector.Group
	GetGroups() []*collector.Group
	VMsMap() map[string]topology.Endpoint
}

func ConfigFromResourcesContainer(recourses *collector.ResourcesContainerModel,
	params common.OutputParameters) (*Config, error) {
	parser := NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()

	// in debug/verbose mode -- print the parsed config
	logging.Debugf("the parsed config details: %s", config.GetConfigInfoStr(params.Color))

	return config, nil
}

// Config captures nsx Config, implements NSXConfig interface
type Config struct {
	Vms         []topology.Endpoint                      // list of all Vms
	VmsMap      map[string]topology.Endpoint             // map from uid to vm objects
	Fw          *dfw.DFW                                 // currently assuming one DFW only (todo: rename pkg dfw)
	Groups      []*collector.Group                       // list of all groups (also these with no Vms)
	GroupsPerVM map[topology.Endpoint][]*collector.Group // map from vm to its groups
}

func (c *Config) DFW() *dfw.DFW {
	return c.Fw
}
func (c *Config) VMs() []topology.Endpoint {
	return c.Vms
}
func (c *Config) VMsMap() map[string]topology.Endpoint {
	return c.VmsMap
}

func (c *Config) VMToGroupsMap() map[topology.Endpoint][]*collector.Group {
	return c.GroupsPerVM
}
func (c *Config) GetGroups() []*collector.Group {
	return c.Groups
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
