package nsx

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/data"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

// this file contains main API for synthesis to NSX policies from abstract model (for testing purposes)

const firstRuleID = 3984
const firstGroupID = 4826

func AbstractToNSXPolicies(rc *collector.ResourcesContainerModel, synthModel *model.AbstractModelSyn) (
	[]collector.SecurityPolicy, []collector.Group) {
	a := newAbsToNXS(synthModel.ExternalIP)
	a.getVMsInfo(rc, synthModel)
	a.convertPolicies(synthModel.Policy, synthModel.SynthesizeAdmin)
	return data.ToPoliciesList(a.categories), a.groups
}

type absToNXS struct {
	labelsVMs  map[string][]topology.Endpoint
	allVMs     []topology.Endpoint
	vmResource map[topology.Endpoint]collector.RealizedVirtualMachine

	categories    []data.Category
	groups        []collector.Group
	ruleIDCounter int
	externalIP    *netset.IPBlock
}

func newAbsToNXS(externalIP *netset.IPBlock) *absToNXS {
	return &absToNXS{
		labelsVMs:  map[string][]topology.Endpoint{},
		vmResource: map[topology.Endpoint]collector.RealizedVirtualMachine{},
		externalIP: externalIP,
	}
}
func (a *absToNXS) getVMsInfo(rc *collector.ResourcesContainerModel, synthModel *model.AbstractModelSyn) {
	a.allVMs = synthModel.VMs
	for i := range rc.DomainList {
		for iGroup := range rc.DomainList[i].Resources.GroupList {
			for iVM := range rc.DomainList[i].Resources.GroupList[iGroup].VMMembers {
				vmResource := rc.DomainList[i].Resources.GroupList[iGroup].VMMembers[iVM]
				vmIndex := slices.IndexFunc(a.allVMs, func(vm topology.Endpoint) bool { return *vmResource.DisplayName == vm.Name() })
				if vmIndex >= 0 {
					a.vmResource[a.allVMs[vmIndex]] = vmResource
				}
			}
		}
	}
	a.labelsVMs = synthModel.LabelsToVMsMap
}

var fwRuleToDataRuleAction = map[dfw.RuleAction]string{
	dfw.ActionAllow:     data.Allow,
	dfw.ActionDeny:      data.Drop,
	dfw.ActionJumpToApp: data.JumpToApp,
}

func (a *absToNXS) convertPolicies(policy []*model.SymbolicPolicy, synthesizeAdmin bool) {
	for _, p := range policy {
		rulesToDirection := map[*[]*model.SymbolicRule]string{&p.Outbound: "OUT", &p.Inbound: "IN"}
		for rules, dir := range rulesToDirection {
			for _, rule := range *rules {
				if synthesizeAdmin && rule.OrigRuleCategory < collector.MinNonAdminCategory() {
					for _, p := range *rule.OrigSymbolicPaths {
						a.pathToRule(p, dir, fwRuleToDataRuleAction[rule.OrigRule.Action], rule.OrigRuleCategory.String())
					}
				} else {
					for _, p := range rule.OptimizedAllowOnlyPaths {
						a.pathToRule(p, dir, data.Allow, collector.LastCategory().String())
					}
				}
			}
		}
	}
	a.addDefaultDenyRule()
}

func (a *absToNXS) addDefaultDenyRule() {
	const defaultDenyID = 9999
	r := a.addNewRule(collector.LastCategory().String())
	r.Action = data.Drop
	r.Source = data.AnyStr
	r.Dest = data.AnyStr
	r.Services = []string{data.AnyStr}
	r.ID = defaultDenyID
	r.Name = "default-deny"
	// default direction is IN_OUT in rule generation, no need to assign direction here
}

func (a *absToNXS) pathToRule(p *symbolicexpr.SymbolicPath, direction, action, categoryType string) {
	rule := a.addNewRule(categoryType)
	rule.Action = action
	rule.Description = action + ": " + p.String()
	rule.Source = a.createGroup(p.Src)
	rule.Dest = a.createGroup(p.Dst)
	rule.Conn = p.Conn
	rule.Direction = direction
	rule.Description = p.String()
}

func (a *absToNXS) addNewRule(categoryType string) *data.Rule {
	categoryIndex := slices.IndexFunc(a.categories, func(c data.Category) bool { return categoryType == c.CategoryType })
	if categoryIndex < 0 {
		categoryIndex = len(a.categories)
		a.categories = append(a.categories, data.Category{
			Name:         categoryType + "_name",
			CategoryType: categoryType,
			Rules:        []data.Rule{},
		})
	}
	category := &a.categories[categoryIndex]
	id := firstRuleID + a.ruleIDCounter
	a.ruleIDCounter++
	rule := data.Rule{
		Name: fmt.Sprintf("ruleName_%d", id),
		ID:   id,
	}
	category.Rules = append(category.Rules, rule)
	return &category.Rules[len(category.Rules)-1]
}

func (a *absToNXS) createGroup(con symbolicexpr.Term) string {
	vms := slices.Clone(a.allVMs)
	for _, atom := range con {
		switch {
		case atom.IsTautology():
			return netset.CidrAll
		case atom.IsAllExternal():
			return a.externalIP.String()
		case atom.IsAllGroups():
			continue
		case atom.GetExternalBlock() != nil:
			return atom.GetExternalBlock().String()
		default:
			label, not := atom.AsSelector()
			atomVMs := a.labelsVMs[label]
			if not {
				atomVMs = topology.Subtract(a.allVMs, atomVMs)
			}
			vms = topology.Intersection(vms, atomVMs)
		}
	}
	if len(vms) == len(a.allVMs) {
		return data.AnyStr
	}
	gID := firstGroupID + len(a.groups)
	gName := fmt.Sprintf("groupName_%d", gID)
	group := collector.Group{}
	group.DisplayName = &gName
	group.Path = &gName
	group.VMMembers = make([]collector.RealizedVirtualMachine, len(vms))
	for i, vm := range vms {
		group.VMMembers[i] = a.vmResource[vm]
	}
	a.groups = append(a.groups, group)
	return *group.Path
}
