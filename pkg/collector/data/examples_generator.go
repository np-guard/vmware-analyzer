package data

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
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
	// defined by VMs
	groupList := []collector.Group{}
	for group, members := range e.GroupsByVMs {
		newGroup := newGroupByExample(group)
		for _, member := range members {
			vmMember := collector.RealizedVirtualMachine{}
			vmMember.RealizedVirtualMachine.DisplayName = &member
			vmMember.RealizedVirtualMachine.Id = &member
			newGroup.VMMembers = append(newGroup.VMMembers, vmMember)
		}
		groupList = append(groupList, newGroup)
	}
	// groups defined by expr
	for group, expr := range e.GroupsByExpr {
		newGroup := newGroupByExample(group)
		groupExpr := expr.exampleExprToExpr()
		newGroup.Expression = *groupExpr
		groupList = append(groupList, newGroup)
	}
	res.DomainList[0].Resources.GroupList = groupList

	// add dfw
	res.DomainList[0].Resources.SecurityPolicyList = ToPoliciesList(e.Policies)
	res.ServiceList = getServices()
	return res
}

func newGroupByExample(name string) collector.Group {
	newGroup := collector.Group{}
	newGroup.Group.DisplayName = &name
	newGroup.Group.Path = &name
	return newGroup
}

func ToPoliciesList(policies []Category) []collector.SecurityPolicy {
	policiesList := []collector.SecurityPolicy{}
	for _, policy := range policies {
		newPolicy := collector.SecurityPolicy{}
		newPolicy.Category = &policy.CategoryType
		newPolicy.DisplayName = &policy.Name
		newPolicy.Scope = []string{AnyStr} // TODO: add scope as configurable
		newPolicy.Rules = make([]collector.Rule, len(policy.Rules))
		newPolicy.SecurityPolicy.Rules = make([]nsx.Rule, len(policy.Rules))
		// add policy rules
		for i := range policy.Rules {
			rule := policy.Rules[i]
			newPolicy.Rules[i] = rule.toCollectorRule()
			newPolicy.SecurityPolicy.Rules[i] = newPolicy.Rules[i].Rule
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
	Tag      nsx.Tag
	NotEqual bool // equal (false) or not equal (true)
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
			Name:         collector.EnvironmentStr,
			CategoryType: collector.EnvironmentStr,
		},
		{
			Name:         collector.ApplicationStr,
			CategoryType: collector.ApplicationStr,
		},
	}
}

const nonTrivialExprSize = 3

func (exp *ExampleExpr) exampleExprToExpr() *collector.Expression {
	cond1 := exp.Cond1.exampleCondToCond()
	if exp.Op == Nop {
		res := collector.Expression{cond1}
		return &res
	}
	res := make(collector.Expression, nonTrivialExprSize)
	res[0] = cond1
	expOp := collector.ConjunctionOperator{}
	conjOp := nsx.ConjunctionOperatorConjunctionOperatorAND
	if exp.Op == Or {
		conjOp = nsx.ConjunctionOperatorConjunctionOperatorOR
	}
	expOp.ConjunctionOperator.ConjunctionOperator = &conjOp
	res[1] = &expOp
	res[2] = exp.Cond2.exampleCondToCond()
	return &res
}

func (cond *ExampleCond) exampleCondToCond() *collector.Condition {
	condKey := nsx.ConditionKeyTag
	memberType := nsx.ConditionMemberTypeVirtualMachine
	operator := nsx.ConditionOperatorEQUALS
	if cond.NotEqual {
		operator = nsx.ConditionOperatorNOTEQUALS
	}
	res := collector.Condition{Condition: nsx.Condition{Key: &condKey, MemberType: &memberType, Operator: &operator,
		Value: &cond.Tag.Tag}}
	res.Condition.Value = &cond.Tag.Tag
	return &res
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
	Conn                 *netset.TransportSet
	Action               string
	Direction            string // if not set, used as default with "IN_OUT"
	Description          string
}

func (r *Rule) toCollectorRule() collector.Rule {
	services, entries := calcServiceAndEntries(r.Services, r.Conn)
	return collector.Rule{
		Rule: nsx.Rule{
			DisplayName:          &r.Name,
			RuleId:               &r.ID,
			Action:               (*nsx.RuleAction)(&r.Action),
			SourceGroups:         []string{r.Source},
			DestinationGroups:    []string{r.Dest},
			SourcesExcluded:      r.SourcesExcluded,
			DestinationsExcluded: r.DestinationsExcluded,
			Services:             services,
			Direction:            r.directionStr(),
			Scope:                []string{AnyStr}, // TODO: add scope as configurable
			Description:          &r.Description,
		},
		ServiceEntries: entries,
	}
}

var codeToProtocol = map[int]nsx.L4PortSetServiceEntryL4Protocol{
	netset.UDPCode: nsx.L4PortSetServiceEntryL4ProtocolUDP,
	netset.TCPCode: nsx.L4PortSetServiceEntryL4ProtocolTCP,
}

// calcServiceAndEntries() take a list of services, and the connection,
// and translate it to a list of services and a list of service entries,
// which represent the union of the services and the connection.
func calcServiceAndEntries(services []string, conn *netset.TransportSet) ([]string, collector.ServiceEntries) {
	if conn == nil {
		// we have only services
		return services, nil
	}
	if conn.IsAll() || slices.Contains(services, AnyStr) {
		// the ANY string will do here:
		return []string{AnyStr}, nil
	}
	// creating entries from the conn:
	entries := collector.ServiceEntries{}
	for _, partition := range conn.TCPUDPSet().Partitions() {
		protocolsCodes := partition.S1.Elements()
		portRanges := partition.S3.Intervals()
		for _, protocolCode := range protocolsCodes {
			entry := &collector.L4PortSetServiceEntry{}
			entry.L4Protocol = common.PointerTo(codeToProtocol[int(protocolCode)])
			for _, portRange := range portRanges {
				var ports nsx.PortElement
				if portRange.Start() == portRange.End() {
					ports = nsx.PortElement(fmt.Sprintf("%d", portRange.Start()))
				} else {
					ports = nsx.PortElement(fmt.Sprintf("%d-%d", portRange.Start(), portRange.End()))
				}
				entry.DestinationPorts = append(entry.DestinationPorts, ports)
			}
			entries = append(entries, entry)
		}
	}
	for _, partition := range conn.ICMPSet().Partitions() {
		types := []*int{nil}
		codes := []*int{nil}
		typesSet := partition.Left
		codesSet := partition.Right
		if !typesSet.Equal(netset.AllICMPTypes()) {
			// in this case each type will have an entry per code:
			types = make([]*int, len(typesSet.Elements()))
			for i, typeNumber := range typesSet.Elements() {
				types[i] = common.PointerTo(int(typeNumber))
			}
		}
		if !codesSet.Equal(netset.AllICMPCodes()) {
			// in this case each code will have an entry per type:
			codes = make([]*int, len(codesSet.Elements()))
			for i, code := range codesSet.Elements() {
				codes[i] = common.PointerTo(int(code))
			}
		}
		// creating len(types) x len(codes) entries:
		for _, t := range types {
			for _, c := range codes {
				entry := &collector.ICMPTypeServiceEntry{}
				entry.IcmpCode = c
				entry.IcmpType = t
				entries = append(entries, entry)
			}
		}
	}
	return services, entries
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
