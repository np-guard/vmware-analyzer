package tests

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

//nolint:gocritic // just for testing
func ExamplesGeneration(e Example) *collector.ResourcesContainerModel {
	res := &collector.ResourcesContainerModel{}
	// add vms
	for _, vmName := range e.vms {
		newVM := nsx.VirtualMachine{
			DisplayName: &vmName,
			ExternalId:  &vmName,
		}
		newVMRes := collector.VirtualMachine{
			VirtualMachine: newVM,
		}
		res.VirtualMachineList = append(res.VirtualMachineList, newVMRes)
	}
	// set default domain
	domainRsc := collector.Domain{}
	defaultName := "default"
	domainRsc.DisplayName = &defaultName
	res.DomainList = append(res.DomainList, domainRsc)

	// add groups
	groupList := []collector.Group{}
	for group, members := range e.groups {
		newGroup := collector.Group{}
		newGroup.Group.DisplayName = &group
		newGroup.Group.Path = &group
		for _, member := range members {
			vmMember := collector.RealizedVirtualMachine{}
			vmMember.RealizedVirtualMachine.DisplayName = &member
			vmMember.RealizedVirtualMachine.Id = &member
			newGroup.VMMembers = append(newGroup.VMMembers, vmMember)
		}
		groupList = append(groupList, newGroup)
	}
	res.DomainList[0].Resources.GroupList = groupList

	// add dfw
	policiesList := []collector.SecurityPolicy{}
	for _, policy := range e.policies {
		newPolicy := collector.SecurityPolicy{}
		newPolicy.Category = &policy.categoryType
		newPolicy.DisplayName = &policy.name
		newPolicy.Scope = []string{anyStr} // TODO: add scope as configurable
		// add policy rules
		for _, rule := range policy.rules {
			newRule := nsx.Rule{
				DisplayName:       &rule.name,
				RuleId:            &rule.id,
				Action:            (*nsx.RuleAction)(&rule.action),
				SourceGroups:      []string{rule.source},
				DestinationGroups: []string{rule.dest},
				Services:          rule.services,
				Direction:         "IN_OUT",         // TODO: add Direction as configurable
				Scope:             []string{anyStr}, // TODO: add scope as configurable
			}
			newPolicy.SecurityPolicy.Rules = append(newPolicy.SecurityPolicy.Rules, newRule)
			collectorRule := collector.Rule{
				Rule: newRule,
			}
			newPolicy.Rules = append(newPolicy.Rules, collectorRule)
		}
		policiesList = append(policiesList, newPolicy)
	}

	res.DomainList[0].Resources.SecurityPolicyList = policiesList

	res.ServiceList = []collector.Service{} // todo not needed here, at least in this stage
	return res
}

// examples generator
const (
	anyStr    = "ANY"
	drop      = "DROP"
	allow     = "ALLOW"
	jumpToApp = "JUMP_TO_APPLICATION"
)

// Example is in s single domain
type Example struct {
	vms            []string
	groups         map[string][]string
	DisjointGroups [][]string
	policies       []category
}

func defaultDenyRule(id int) rule {
	return rule{
		name:     "default-deny-rule",
		id:       id,
		source:   anyStr,
		dest:     anyStr,
		services: []string{anyStr},
		action:   drop,
	}
}

type rule struct {
	name     string
	id       int
	source   string
	dest     string
	services []string
	action   string
}

type category struct {
	name         string
	categoryType string
	rules        []rule
	// TODO: add scope, consider other fields
}
