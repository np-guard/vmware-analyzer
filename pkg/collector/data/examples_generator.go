package data

import (
	"os"
	"path/filepath"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

func ExamplesGeneration(e Example) *collector.ResourcesContainerModel {
	res := &collector.ResourcesContainerModel{}
	// add Vms
	for _, vmName := range e.Vms {
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
	for group, members := range e.Groups {
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
	for _, policy := range e.Policies {
		newPolicy := collector.SecurityPolicy{}
		newPolicy.Category = &policy.CategoryType
		newPolicy.DisplayName = &policy.Name
		newPolicy.Scope = []string{anyStr} // TODO: add scope as configurable
		// add policy rules
		for _, rule := range policy.Rules {
			newRule := nsx.Rule{
				DisplayName:       &rule.Name,
				RuleId:            &rule.Id,
				Action:            (*nsx.RuleAction)(&rule.Action),
				SourceGroups:      []string{rule.Source},
				DestinationGroups: []string{rule.Dest},
				Services:          rule.Services,
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

	res.ServiceList = getServices()
	return res
}

// examples generator
const (
	anyStr    = "ANY"
	Drop      = "DROP"
	Allow     = "ALLOW"
	JumpToApp = "JUMP_TO_APPLICATION"
)

// Example is in s single domain
type Example struct {
	Vms      []string
	Groups   map[string][]string
	Policies []Category
}

func DefaultDenyRule(id int) Rule {
	return Rule{
		Name:     "default-deny-Rule",
		Id:       id,
		Source:   anyStr,
		Dest:     anyStr,
		Services: []string{anyStr},
		Action:   Drop,
	}
}

type Rule struct {
	Name     string
	Id       int
	Source   string
	Dest     string
	Services []string
	Action   string
}

type Category struct {
	Name         string
	CategoryType string
	Rules        []Rule
	// TODO: add scope, consider other fields
}

func getServices() []collector.Service {
	servicesFilePath := filepath.Join(projectpath.Root, "pkg", "collector", "data", "Services.json")
	inputConfigContent, err := os.ReadFile(servicesFilePath)
	if err != nil {
		return nil
	}
	rc, err := collector.FromJSONString(inputConfigContent)
	if err != nil {
		return nil
	}
	return rc.ServiceList
}
