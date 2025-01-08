package data

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

func ExamplesGeneration(e Example) *collector.ResourcesContainerModel {
	res := &collector.ResourcesContainerModel{}
	// add vms
	for _, vmName := range e.VMs {
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
		newPolicy.Category = &policy.categoryType
		newPolicy.DisplayName = &policy.name
		newPolicy.Scope = []string{AnyStr} // TODO: add scope as configurable
		// add policy rules
		for _, rule := range policy.rules {
			newRule := rule.toNSXRule()
			newPolicy.SecurityPolicy.Rules = append(newPolicy.SecurityPolicy.Rules, *newRule)
			collectorRule := collector.Rule{
				Rule: *newRule,
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
	AnyStr    = "ANY"
	Drop      = "DROP"
	Allow     = "ALLOW"
	JumpToApp = "JUMP_TO_APPLICATION"
)

// Example is in s single domain
type Example struct {
	VMs      []string
	Groups   map[string][]string
	Policies []category
}

func (e *Example) CopyTopology() *Example {
	res := &Example{}
	res.VMs = slices.Clone(e.VMs)
	res.Groups = map[string][]string{}
	maps.Copy(res.Groups, e.Groups)
	return res
}

/*
Policies: []category{
		{
			name:         "app-x",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "allow_smb_incoming",
					id:       1004,
					source:   "frontend",
					dest:     "backend",
					services: []string{"/infra/services/SMB"},
					action:   Allow,
				},
				defaultDenyRule(denyRuleIDApp),
			},
		},
	},
*/

func (e *Example) InitEmptyEnvAppCategories() {
	e.Policies = []category{
		{
			name:         dfw.EnvironmentStr,
			categoryType: dfw.EnvironmentStr,
		},
		{
			name:         dfw.ApplicationStr,
			categoryType: dfw.ApplicationStr,
		},
	}
}

func (e *Example) AddRuleToExampleInCategory(categoryType string, ruleToAdd *Rule) error {
	// assuming env/app categories already initialized
	categoryIndex := slices.IndexFunc(e.Policies, func(c category) bool { return c.categoryType == categoryType })
	if categoryIndex < 0 {
		return fmt.Errorf("could not find category type %s in example object", categoryType)
	}

	// set rule ID by index in rules list
	ruleToAdd.ID = 1
	if numRulesCurrent := len(e.Policies[categoryIndex].rules); numRulesCurrent > 0 {
		ruleToAdd.ID = numRulesCurrent + 1
	}
	if categoryIndex > 0 {
		ruleToAdd.ID += len(e.Policies[categoryIndex-1].rules)
	}

	// add the rule as last in the rules list of the given category
	e.Policies[categoryIndex].rules = append(e.Policies[categoryIndex].rules, *ruleToAdd)
	return nil
}

func defaultDenyRule(id int) Rule {
	return Rule{
		Name:     "default-deny-rule",
		ID:       id,
		Source:   AnyStr,
		Dest:     AnyStr,
		Services: []string{AnyStr},
		Action:   Drop,
	}
}

type Rule struct {
	Name      string
	ID        int
	Source    string
	Dest      string
	Services  []string
	Action    string
	Direction string // if not set, used as default with "IN_OUT"
}

func (r *Rule) toNSXRule() *nsx.Rule {
	return &nsx.Rule{
		DisplayName:       &r.Name,
		RuleId:            &r.ID,
		Action:            (*nsx.RuleAction)(&r.Action),
		SourceGroups:      []string{r.Source},
		DestinationGroups: []string{r.Dest},
		Services:          r.Services,
		Direction:         r.directionStr(),
		Scope:             []string{AnyStr}, // TODO: add scope as configurable
	}
}

/*
const RuleDirectionIN RuleDirection = "IN"
const RuleDirectionINOUT RuleDirection = "IN_OUT"
const RuleDirectionOUT RuleDirection = "OUT"

var enumValues_RuleDirection = []interface{}{
	"IN",
	"OUT",
	"IN_OUT",
}
*/

func (r *Rule) directionStr() nsx.RuleDirection {
	switch r.Direction {
	case string(nsx.RuleDirectionIN):
		return nsx.RuleDirectionIN
	case string(nsx.RuleDirectionOUT):
		return nsx.RuleDirectionOUT
	default:
		return nsx.RuleDirectionINOUT // use as default direction if not specified
	}
}

type category struct {
	name         string
	categoryType string
	rules        []Rule
	// TODO: add scope, consider other fields
}

func getServices() []collector.Service {
	servicesFilePath := filepath.Join(projectpath.Root, "pkg", "collector", "data", "services.json")
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
