package synthesis

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/data"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
)

const firstRuleID = 3984
const firstGroupID = 4826

func toNSXPolicies(rc *collector.ResourcesContainerModel, model *AbstractModelSyn) ([]collector.SecurityPolicy, []collector.Group) {
	a := newAbsToNXS(model.ExternalIP)
	a.getVMsInfo(rc, model)
	a.convertPolicies(model.policy, model.synthesizeAdmin)
	return data.ToPoliciesList(a.categories), a.groups
}

type absToNXS struct {
	vmLabels   map[topology.Endpoint][]string
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
		vmLabels:   map[topology.Endpoint][]string{},
		labelsVMs:  map[string][]topology.Endpoint{},
		vmResource: map[topology.Endpoint]collector.RealizedVirtualMachine{},
		externalIP: externalIP,
	}
}
func (a *absToNXS) getVMsInfo(rc *collector.ResourcesContainerModel, model *AbstractModelSyn) {
	a.allVMs = model.vms
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
	for _, vm := range a.allVMs {
		addVMLabel := func(vm topology.Endpoint, label string) {
			a.vmLabels[vm] = append(a.vmLabels[vm], label)
			a.labelsVMs[label] = append(a.labelsVMs[label], vm)
		}
		for _, tag := range vm.Tags() {
			label, _ := symbolicexpr.NewTagTerm(tag, false).AsSelector()
			addVMLabel(vm, label)
		}
		for _, group := range model.epToGroups[vm] {
			label, _ := symbolicexpr.NewGroupAtomicTerm(group, false).AsSelector()
			addVMLabel(vm, label)
		}
		for _, segment := range model.vmSegments[vm] {
			label, _ := symbolicexpr.NewSegmentTerm(segment, false).AsSelector()
			addVMLabel(vm, label)
		}
		for _, ruleIPBlock := range model.ruleBlockPerEP[vm] {
			if !ruleIPBlock.IsAll() {
				label, _ := symbolicexpr.NewInternalIPTerm(ruleIPBlock, false).AsSelector()
				addVMLabel(vm, label)
			}
		}
	}
}

var fwRuleToDataRuleAction = map[dfw.RuleAction]string{
	dfw.ActionAllow:     data.Allow,
	dfw.ActionDeny:      data.Drop,
	dfw.ActionJumpToApp: data.JumpToApp,
}

func (a *absToNXS) convertPolicies(policy []*symbolicPolicy, synthesizeAdmin bool) {
	for _, p := range policy {
		rulesToDirection := map[*[]*symbolicRule]string{&p.outbound: "OUT", &p.inbound: "IN"}
		for rules, dir := range rulesToDirection {
			for _, rule := range *rules {
				if synthesizeAdmin && rule.origRuleCategory < collector.MinNonAdminCategory() {
					for _, p := range *rule.origSymbolicPaths {
						a.pathToRule(p, dir, fwRuleToDataRuleAction[rule.origRule.Action], rule.origRuleCategory.String())
					}
				} else {
					for _, p := range rule.optimizedAllowOnlyPaths {
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

func (a *absToNXS) createGroup(con symbolicexpr.Conjunction) string {
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
