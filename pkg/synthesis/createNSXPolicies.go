package synthesis

import (
	"fmt"
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

func toNSXPolicies(rc *collector.ResourcesContainerModel, model *AbstractModelSyn) ([]collector.SecurityPolicy, []collector.Group) {
	a := newAbsToNXS()
	a.getVMsInfo(rc, model)
	a.convertPolicies(model.policy)
	return data.ToPoliciesList([]data.Category{a.category}), a.groups
}

type absToNXS struct {
	vmLabels   map[*endpoints.VM][]string
	labelsVMs  map[string][]*endpoints.VM
	allVMs     []*endpoints.VM
	vmResource map[*endpoints.VM]collector.RealizedVirtualMachine

	category data.Category
	groups   []collector.Group
}

func newAbsToNXS() *absToNXS {
	return &absToNXS{
		category: data.Category{
			Name:         "default",
			CategoryType: "Application",
			Rules:        []data.Rule{},
		},
		vmLabels:   map[*endpoints.VM][]string{},
		labelsVMs:  map[string][]*endpoints.VM{},
		vmResource: map[*endpoints.VM]collector.RealizedVirtualMachine{},
	}
}
func (a *absToNXS) getVMsInfo(rc *collector.ResourcesContainerModel, model *AbstractModelSyn) {
	a.allVMs = model.vms
	for iGroup := range rc.DomainList[0].Resources.GroupList {
		for iVM := range rc.DomainList[0].Resources.GroupList[iGroup].VMMembers {
			vmResource := rc.DomainList[0].Resources.GroupList[iGroup].VMMembers[iVM]
			vmIndex := slices.IndexFunc(a.allVMs, func(vm *endpoints.VM) bool { return *vmResource.DisplayName == vm.Name() })
			if vmIndex >= 0 {
				a.vmResource[a.allVMs[vmIndex]] = vmResource
			}
		}
	}
	for _, vm := range a.allVMs {
		for _, group := range model.epToGroups[vm] {
			label, _ := symbolicexpr.NewAtomicTerm(group, group.Name(), false).AsSelector()
			a.vmLabels[vm] = append(a.vmLabels[vm], label)
			a.labelsVMs[label] = append(a.labelsVMs[label], vm)
		}
	}
}

func (a *absToNXS) convertPolicies(policy []*symbolicPolicy) {
	for _, p := range policy {
		for _, ob := range p.outbound {
			for _, p := range ob.allowOnlyRulePaths {
				a.pathToRule(p, "OUT")
			}
		}
		for _, ib := range p.inbound {
			for _, p := range ib.allowOnlyRulePaths {
				a.pathToRule(p, "IN")
			}
		}
	}
}

func (a *absToNXS) pathToRule(p *symbolicexpr.SymbolicPath, direction string) {
	srcGroup, dstGroup, services := a.toGroupsAndService(p)
	rule := a.addNewRule(p.String())
	rule.Source = srcGroup
	rule.Dest = dstGroup
	rule.Services = services
	rule.Direction = direction
}

func (a *absToNXS) toGroupsAndService(p *symbolicexpr.SymbolicPath) (src, dst string, service []string) {
	srcVMs := a.createGroup(p.Src)
	dstVMs := a.createGroup(p.Dst)
	services := []string{data.AnyStr} // todo
	return srcVMs, dstVMs, services
}

func (a *absToNXS) addNewRule(description string) *data.Rule {
	id := 1000 + len(a.category.Rules)
	rule := data.Rule{
		Name:        fmt.Sprintf("ruleName_%d", id),
		ID:          id,
		Action:      data.Allow,
		Description: description,
	}
	a.category.Rules = append(a.category.Rules, rule)
	return &a.category.Rules[len(a.category.Rules)-1]
}

func (a *absToNXS) createGroup(con symbolicexpr.Conjunction) string {
	vms := slices.Clone(a.allVMs)
	for _, atom := range con {
		if atom.IsTautology() {
			continue
		}
		label, not := atom.AsSelector()
		atomVMs := a.labelsVMs[label]
		if not {
			atomVMs = endpoints.Subtract(a.allVMs, atomVMs)
		}
		vms = endpoints.Intersection(vms, atomVMs)
	}
	if len(vms) == len(a.allVMs) {
		return data.AnyStr
	}
	gID := 2000 + len(a.groups)
	gName := fmt.Sprintf("groupName_%d", gID)
	group := collector.Group{}
	group.Group.DisplayName = &gName
	group.Group.Path = &gName
	group.VMMembers = make([]collector.RealizedVirtualMachine, len(vms))
	for i, vm := range vms {
		group.VMMembers[i] = a.vmResource[vm]
	}
	a.groups = append(a.groups, group)
	return *group.Path
}
