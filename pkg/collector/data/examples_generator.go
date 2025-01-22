package data

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

func ExamplesGeneration(e *Example) *collector.ResourcesContainerModel {
	res := &collector.ResourcesContainerModel{}
	// add vms
	for _, vmName := range e.VMs {
		newVM := nsx.VirtualMachine{
			DisplayName: &vmName,
			ExternalId:  &vmName,
		}
		// vm has tags?
		if vmTags, ok := e.VMsTags[vmName]; ok {
			newVM.Tags = vmTags
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
	for group, members := range e.GroupsByVMs {
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
	res.DomainList[0].Resources.SecurityPolicyList = ToPoliciesList(e.Policies)
	res.ServiceList = getServices()
	return res
}

func ToPoliciesList(policies []Category) []collector.SecurityPolicy {
	policiesList := []collector.SecurityPolicy{}
	for _, policy := range policies {
		newPolicy := collector.SecurityPolicy{}
		newPolicy.Category = &policy.CategoryType
		newPolicy.DisplayName = &policy.Name
		newPolicy.Scope = []string{AnyStr} // TODO: add scope as configurable
		// add policy rules
		for i := range policy.Rules {
			rule := policy.Rules[i]
			newRule := rule.toNSXRule()
			newPolicy.SecurityPolicy.Rules = append(newPolicy.SecurityPolicy.Rules, *newRule)
			collectorRule := collector.Rule{
				Rule: *newRule,
			}
			newPolicy.Rules = append(newPolicy.Rules, collectorRule)
		}
		policiesList = append(policiesList, newPolicy)
	}
	return policiesList
}

// examples generator
const (
	AnyStr    = "ANY"
	Drop      = "DROP"
	Allow     = "ALLOW"
	JumpToApp = "JUMP_TO_APPLICATION"
)

// example expr struct to ease testing
// example_cond -> <Tag_scope> eq/new val
// example_expr ->  example_cond | example_cond and/or example_cond

type ExampleOp int

const (
	Nop ExampleOp = iota
	And
	Or
)

type ExampleCond struct {
	Scope string // optional; can be empty // todo
	Tag   string // todo
	Equal bool   // equal (true) or not equal (false)
}

// ExampleExpr equiv to example_expr described above
// if op is nop then only cond1 is considered and exampleExpr is actually exampleCond; Cond2 is empty in that case
type ExampleExpr struct {
	Cond1 ExampleCond
	Op    ExampleOp
	Cond2 ExampleCond
}

// Example is in s single domain
type Example struct {
	// config spec fields below
	VMs          []string
	VMsTags      map[string][]nsx.Tag
	GroupsByVMs  map[string][]string
	GroupsByExpr map[string]ExampleExpr
	Policies     []Category

	// JSON generation fields below
	Name string // example name for JSON file name
}

var dataPkgPath = filepath.Join(projectpath.Root, "pkg", "collector", "data")

func getExamplesJSONPath(name string) string {
	return filepath.Join(dataPkgPath, "json", name+".json")
}

func (e *Example) StoreAsJSON(override bool) error {
	jsonPath := getExamplesJSONPath(e.Name)
	if !override {
		if _, err := os.Stat(jsonPath); err == nil {
			// jsonPath exists
			return nil
		}
	}
	rc := ExamplesGeneration(e)
	rcJSON, err := rc.ToJSONString()
	if err != nil {
		return err
	}
	return common.WriteToFile(jsonPath, rcJSON)
}

func (e *Example) CopyTopology() *Example {
	res := &Example{}
	res.VMs = slices.Clone(e.VMs)
	res.GroupsByVMs = map[string][]string{}
	maps.Copy(res.GroupsByVMs, e.GroupsByVMs)
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
	e.Policies = []Category{
		{
			Name:         dfw.EnvironmentStr,
			CategoryType: dfw.EnvironmentStr,
		},
		{
			Name:         dfw.ApplicationStr,
			CategoryType: dfw.ApplicationStr,
		},
	}
}

func (e *Example) AddRuleToExampleInCategory(categoryType string, ruleToAdd *Rule) error {
	// assuming env/app categories already initialized
	categoryIndex := slices.IndexFunc(e.Policies, func(c Category) bool { return c.CategoryType == categoryType })
	if categoryIndex < 0 {
		return fmt.Errorf("could not find category type %s in example object", categoryType)
	}

	// set rule ID by index in rules list
	ruleToAdd.ID = 1
	if numRulesCurrent := len(e.Policies[categoryIndex].Rules); numRulesCurrent > 0 {
		ruleToAdd.ID = numRulesCurrent + 1
	}
	if categoryIndex > 0 {
		ruleToAdd.ID += len(e.Policies[categoryIndex-1].Rules)
	}

	// add the rule as last in the rules list of the given category
	e.Policies[categoryIndex].Rules = append(e.Policies[categoryIndex].Rules, *ruleToAdd)
	return nil
}

func DefaultDenyRule(id int) Rule {
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
	Name                 string
	ID                   int
	Source               string
	SourcesExcluded      bool
	Dest                 string
	DestinationsExcluded bool
	Services             []string
	Action               string
	Direction            string // if not set, used as default with "IN_OUT"
	Description          string
}

func (r *Rule) toNSXRule() *nsx.Rule {
	return &nsx.Rule{
		DisplayName:          &r.Name,
		RuleId:               &r.ID,
		Action:               (*nsx.RuleAction)(&r.Action),
		SourceGroups:         []string{r.Source},
		DestinationGroups:    []string{r.Dest},
		SourcesExcluded:      r.SourcesExcluded,
		DestinationsExcluded: r.DestinationsExcluded,
		Services:             r.Services,
		Direction:            r.directionStr(),
		Scope:                []string{AnyStr}, // TODO: add scope as configurable
		Description:          &r.Description,
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

type Category struct {
	Name         string
	CategoryType string
	Rules        []Rule
	// TODO: add scope, consider other fields
}

func getServices() []collector.Service {
	servicesFilePath := filepath.Join(dataPkgPath, "services.json")
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
