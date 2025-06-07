package configuration

import (
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"

	"github.com/np-guard/vmware-analyzer/pkg/logging"

	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

func ConfigFromResourcesContainer(resources *collector.ResourcesContainerModel,
	params *common.OutputParameters) (*Config, error) {
	filterResources(resources, params.VMs)
	parser := newNSXConfigParserFromResourcesContainer(resources)
	err := parser.runParser()
	if err != nil {
		return nil, err
	}
	config := parser.getConfig()

	// in debug/verbose mode -- print the parsed config
	logging.Infof("the parsed config details: %s", config.getConfigInfoStr(params.Color))
	logging.Debugf("additional config info: %s", config.additionalConfigInfo(params.Color))

	logging.Debug2f("the dfw evaluated rules details:\n%s", config.FW.AllEvaluatedRulesDetails())

	return config, nil
}

// Config captures nsx Config, implements NSXConfig interface
type Config struct {
	VMs               []topology.Endpoint // list of all Vms
	segments          []*topology.SegmentDetails
	PathToSegmentsMap map[string]*topology.Segment             // map from path to segment
	externalIPs       []topology.Endpoint                      // list of all external ips
	VMsMap            map[string]topology.Endpoint             // map from uid to vm objects
	FW                *dfw.DFW                                 // currently assuming one DFW only (todo: rename pkg dfw)
	Groups            []*collector.Group                       // list of all groups (also these with no Vms)
	GroupsPerVM       map[topology.Endpoint][]*collector.Group // map from vm to its groups
	PathToGroupsMap   map[string]*collector.Group              // map from path to group
	configSummary     *configInfo
	origNSXResources  *collector.ResourcesContainerModel
	Topology          *nsxTopology
}

func (c *Config) Endpoints() []topology.Endpoint {
	return append(c.VMs, c.externalIPs...)
}

func (c *Config) GetVMs(collectorVMs []*collector.VirtualMachine) (res []*topology.VM) {
	for _, vm := range collectorVMs {
		if vm.ExternalId == nil {
			return nil
		}
		id := *vm.ExternalId
		if vmObj, ok := c.VMsMap[id]; ok {
			res = append(res, vmObj.(*topology.VM))
		}
	}
	return res
}

// additionalConfigInfo returns mode details about parsed config, related to ip addresses
func (c *Config) additionalConfigInfo(color bool) string {
	sections := &common.SectionsOutput{}

	c.getIPRangeInfoStr(sections, color)
	c.getExternalEPInfoStr(sections, color)
	c.getInternalEPInfoStr(sections, color)
	c.getRuleBlocksStr(sections, color)

	return sections.GenerateSectionsString()
}

// getConfigInfoStr returns string describing the captured configuration content
func (c *Config) getConfigInfoStr(color bool) string {
	sections := &common.SectionsOutput{}

	c.getVMsInfoStr(sections, color)
	c.getSegmentsInfoStr(sections, color)
	c.getSegmentsPortsInfoStr(sections, color)
	c.getVMGroupsStr(sections, color)
	c.getGroupDefinitions(sections, color)
	c.getDFWInfoStr(sections, color)

	return sections.GenerateSectionsString()
}

func (c *Config) AllConfigInfoStr() string {
	return c.getConfigInfoStr(false) + c.additionalConfigInfo(false)
}

const (
	vmNameTitle      = "VM Name"
	vmsTitle         = "VMs"
	segmentNameTitle = "Segment Name"
)

func (c *Config) getVMsInfoStr(sections *common.SectionsOutput, color bool) {
	section := "VMs:"
	header := []string{vmNameTitle, "VM ID", "VM Addresses"}
	lines := [][]string{}
	for _, vm := range c.VMs {
		lines = append(lines, []string{vm.Name(), vm.ID(), strings.Join(vm.(*topology.VM).IPAddresses(), common.CommaSeparator)})
	}
	tableStr := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	sections.AddSection(section, tableStr)
}

func (c *Config) getSegmentsInfoStr(sections *common.SectionsOutput, color bool) {
	section := "Segments:"
	header := []string{"Type", "overlay/vlan", segmentNameTitle, "Segment ID", "Segment CIDRs", "VLAN IDs", vmsTitle}
	lines := [][]string{}
	for _, s := range c.segments {
		vmsStr := common.JoinStringifiedSlice(s.VMs(), common.CommaSeparator)
		lines = append(lines, []string{s.SegmentType(), s.OverlayOrVlan(), s.Name(), s.ID(), s.CIDRs(), s.VlanIDs(), vmsStr})
	}
	tableStr := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	sections.AddSection(section, tableStr)
}

func (c *Config) getSegmentsPortsInfoStr(sections *common.SectionsOutput, color bool) {
	section := "Segments ports:"
	header := []string{segmentNameTitle, "Port Name", "Port UID", vmNameTitle}
	lines := [][]string{}
	for _, s := range c.segments {
		for _, p := range s.PortsDetails() {
			lines = append(lines, p.ToStrSlice())
		}
	}
	tableStr := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	sections.AddSection(section, tableStr)
}

func (c *Config) getVMGroupsStr(sections *common.SectionsOutput, color bool) {
	section := "Groups per VMs:"
	header := []string{"VM", "Groups"}
	lines := [][]string{}
	for vm, groups := range c.GroupsPerVM {
		groupsStr := common.SortedJoinCustomStrFuncSlice(groups,
			func(g *collector.Group) string { return *g.DisplayName }, common.CommaSpaceSeparator)
		lines = append(lines, []string{vm.Name(), groupsStr})
	}
	tableStr := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	sections.AddSection(section, tableStr)
}

func (c *Config) getGroupDefinitions(sections *common.SectionsOutput, color bool) {
	section := "Groups definitions:"
	content := c.GetGroupsStr(color)
	sections.AddSection(section, content)
}

func (c *Config) getDFWInfoStr(sections *common.SectionsOutput, color bool) {
	section := "DFW:"
	content := c.FW.OriginalRulesStrFormatted(color)
	sections.AddSection(section, content)
}

func (c *Config) getIPRangeInfoStr(sections *common.SectionsOutput, color bool) {
	section := "IP Ranges info:"
	header := []string{"Total", "Internal", "External"}
	lines := [][]string{{
		common.IPBlockShortString(c.Topology.allIPBlock),
		common.IPBlockShortString(c.Topology.allInternalIPBlock),
		common.IPBlockShortString(c.Topology.AllExternalIPBlock),
	}}
	table := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	sections.AddSection(section, table)
}

func (c *Config) getExternalEPInfoStr(sections *common.SectionsOutput, color bool) {
	section := "External Endpoints:"
	header := []string{"External EP", "Rule Blocks"}
	lines := [][]string{}
	for _, ip := range c.externalIPs {
		lines = append(lines, []string{ip.IPAddressesStr(), common.SortedJoinCustomStrFuncSlice(c.Topology.RuleBlockPerEP[ip],
			func(ruleBlock *topology.RuleIPBlock) string { return ruleBlock.OriginalIP }, common.CommaSpaceSeparator)})
	}
	table := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	sections.AddSection(section, table)
}
func (c *Config) getInternalEPInfoStr(sections *common.SectionsOutput, color bool) {
	section := "Internal Endpoints:"
	header := []string{"Internal IP", segmentNameTitle, vmsTitle}
	lines := [][]string{}
	vmWithAddressedSegments := []*topology.VM{}
	for _, s := range c.segments {
		if s.CIDRs() != "" {
			vmWithAddressedSegments = append(vmWithAddressedSegments, s.VMs()...)
			vmsStr := common.JoinStringifiedSlice(s.VMs(), common.CommaSeparator)
			lines = append(lines, []string{s.CIDRs(), s.Name(), vmsStr})
		}
	}
	for _, vm := range c.VMs {
		if slices.Index(vmWithAddressedSegments, vm.(*topology.VM)) < 0 {
			for _, address := range vm.(*topology.VM).IPAddresses() {
				lines = append(lines, []string{address, "", vm.Name()})
			}
		}
	}
	table := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	sections.AddSection(section, table)
}

func (c *Config) getRuleBlocksStr(sections *common.SectionsOutput, color bool) {
	section := "Rule Blocks info:"
	header := []string{"Rule Block", "External Endpoints", vmsTitle}
	lines := [][]string{}
	for _, block := range c.Topology.AllRuleIPBlocks {
		eps := common.SortedJoinCustomStrFuncSlice(block.ExternalIPs,
			func(ep topology.Endpoint) string { return ep.Name() }, common.CommaSpaceSeparator)
		vms := common.SortedJoinCustomStrFuncSlice(block.VMs,
			func(vm topology.Endpoint) string { return vm.Name() }, common.CommaSpaceSeparator)
		lines = append(lines, []string{block.OriginalIP, eps, vms})
	}
	table := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	sections.AddSection(section, table)
}

func (c *Config) GetGroupsStr(color bool) string {
	// todo: identify here cases in which we were unable to process expr

	// split to various small tables per component type - for readaility
	var headers = map[string][]string{} // map from copmonent type to table header
	var tablesLines = map[string][][]string{}

	const (
		expressionComponent string = "Expression"
		vmsComponent        string = "VMs"
		addressesComponent  string = "Addresses"
		segmentsComponent   string = "Segments"
		nodesComponent      string = "Transport Nodes"
		ipGroupsComponent   string = "IP Groups"
	)

	componentTypes := []string{expressionComponent, vmsComponent, addressesComponent, segmentsComponent, nodesComponent, ipGroupsComponent}
	for _, component := range componentTypes {
		headers[component] = []string{"Group Name", component}
	}

	for _, group := range c.Groups {
		groupName := *group.DisplayName

		// vms components
		groupVMNames := common.JoinCustomStrFuncSlice(group.VMMembers,
			func(vm collector.RealizedVirtualMachine) string { return *vm.DisplayName },
			common.CommaSpaceSeparator)
		if groupVMNames != "" {
			tablesLines[vmsComponent] = append(tablesLines[vmsComponent], []string{groupName, groupVMNames})
		}

		displayNameFunc := func(res nsx.PolicyGroupMemberDetails) string { return *res.DisplayName }

		// address components
		addresses := common.JoinCustomStrFuncSlice(group.AddressMembers,
			func(a nsx.IPElement) string { return string(a) },
			common.CommaSpaceSeparator)
		if addresses != "" {
			tablesLines[addressesComponent] = append(tablesLines[addressesComponent], []string{groupName, addresses})
		}

		// segments components
		groupSegmentsNames := common.JoinCustomStrFuncSlice(group.Segments, displayNameFunc, common.CommaSpaceSeparator)
		if groupSegmentsNames != "" {
			tablesLines[segmentsComponent] = append(tablesLines[segmentsComponent], []string{groupName, groupSegmentsNames})
		}

		// nodes components
		transportNodesNames := common.JoinCustomStrFuncSlice(group.TransportNodes, displayNameFunc, common.CommaSpaceSeparator)
		if transportNodesNames != "" {
			tablesLines[nodesComponent] = append(tablesLines[nodesComponent], []string{groupName, transportNodesNames})
		}

		// ip-groups components
		ipGrpoupsNames := common.JoinCustomStrFuncSlice(group.IPGroups, displayNameFunc, common.CommaSpaceSeparator)
		if ipGrpoupsNames != "" {
			tablesLines[ipGroupsComponent] = append(tablesLines[ipGroupsComponent], []string{groupName, ipGrpoupsNames})
		}

		// expr components
		groupExprStr := ""
		if len(group.Expression) > 0 {
			groupExprStr = group.Expression.String()
		}
		if groupExprStr != "" {
			tablesLines[expressionComponent] = append(tablesLines[expressionComponent], []string{groupName, groupExprStr})
		}
	}

	var componentToTableStrFunc = func(c string) string {
		if len(tablesLines[c]) == 0 {
			return ""
		}
		return common.GenerateTableString(headers[c], tablesLines[c], &common.TableOptions{SortLines: true, Colors: color})
	}

	return common.JoinCustomStrFuncSlice(componentTypes, componentToTableStrFunc, common.NewLine)
}

func (c *Config) DefaultDenyRule() *dfw.FwRule {
	for _, category := range c.FW.CategoriesSpecs {
		if category.Category == collector.LastCategory() {
			return category.SearchDefaultDenyRule()
		}
	}
	return nil
}
