package data

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
)

// Example is in s single domain
type Example struct {
	// nsx config spec fields below
	VMs           []string
	VMsTags       map[string][]nsx.Tag
	VMsAddress    map[string]string
	GroupsByVMs   map[string][]string
	SegmentsByVMs map[string][]string
	SegmentsBlock map[string]string
	GroupsByExpr  map[string]ExampleExpr // map from group name to its expr
	Policies      []Category

	// additional info about example, relevant for synthesis
	DisjointGroupsTags [][]string

	// JSON generation fields below
	Name string // example name for JSON file name
}

// ExamplesGeneration - main function to generate ResourcesContainerModel from specified Example object.
// It also stores the generated example in the path pkg/data/json .
func ExamplesGeneration(e *Example, overrideJSON bool) (*collector.ResourcesContainerModel, error) {
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
	for segmentName, ip := range e.SegmentsBlock {
		segment := collector.Segment{
			Segment: nsx.Segment{
				UniqueId:    &segmentName,
				DisplayName: &segmentName,
				Subnets:     []nsx.SegmentSubnet{{Network: &ip}},
				Path:        &segmentName,
			},
		}
		for _, vm := range e.SegmentsByVMs[segmentName] {
			portName := "port_" + vm
			port := collector.SegmentPort{
				SegmentPort: nsx.SegmentPort{
					DisplayName: &portName,
					UniqueId:    &portName,
					ParentPath:  &segmentName,
					Attachment: &nsx.PortAttachment{
						Id: &portName,
					},
				},
			}
			vmAddress := nsx.IPAddress(e.VMsAddress[vm])
			vni := collector.VirtualNetworkInterface{
				VirtualNetworkInterface: nsx.VirtualNetworkInterface{
					LportAttachmentId: &portName,
					OwnerVmId:         &vm,
					IpAddressInfo:     []nsx.IpAddressInfo{{IpAddresses: []nsx.IPAddress{vmAddress}}},
				},
			}
			res.VirtualNetworkInterfaceList = append(res.VirtualNetworkInterfaceList, vni)
			segment.SegmentPorts = append(segment.SegmentPorts, port)
		}
		res.SegmentList = append(res.SegmentList, segment)
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
		newGroup.VMMembers = addVMsToGroup(members)
		groupList = append(groupList, newGroup)
	}
	// groups defined by expr and VMs
	for group, expr := range e.GroupsByExpr {
		newGroup := newGroupByExample(group)
		groupExpr := expr.exampleExprToExpr()
		newGroup.Expression = *groupExpr
		realizedVmsList := vmsOfExpr(&res.VirtualMachineList, &newGroup.Expression)
		newGroup.VMMembers = realizedVmsList
		groupList = append(groupList, newGroup)
	}
	res.DomainList[0].Resources.GroupList = groupList

	// add dfw
	res.DomainList[0].Resources.SecurityPolicyList = ToPoliciesList(e.Policies)
	res.ServiceList = getServices()

	// store the example resources object generated as JSON file
	if err := e.storeAsJSON(overrideJSON, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (e *Example) storeAsJSON(override bool, rc *collector.ResourcesContainerModel) error {
	if e.Name == "" {
		return fmt.Errorf("invalid example with empty name")
	}
	jsonPath := GetExamplesJSONPath(e.Name)
	if !override {
		if _, err := os.Stat(jsonPath); err == nil {
			// jsonPath exists - not re-generating
			return nil
		}
	}
	rcJSON, err := rc.ToJSONString()
	if err != nil {
		return err
	}
	return common.WriteToFile(jsonPath, rcJSON)
}

func addVMsToGroup(members []string) []collector.RealizedVirtualMachine {
	res := make([]collector.RealizedVirtualMachine, len(members))
	for i, member := range members {
		vmMember := collector.RealizedVirtualMachine{}
		vmMember.RealizedVirtualMachine.DisplayName = &member
		vmMember.RealizedVirtualMachine.Id = &member
		res[i] = vmMember
	}
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

var dataPkgPath = filepath.Join(projectpath.Root, "pkg", "data")

func GetExamplesJSONPath(name string) string {
	return filepath.Join(dataPkgPath, "json", name+".json")
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

// todo: should be generalized and moved elsewhere?
func getVMsOfTagOrNotTag(vmList *[]collector.VirtualMachine, tag string, resTagNotExist bool) []collector.VirtualMachine {
	res := []collector.VirtualMachine{}
	for i := range *vmList {
		tagExist := tagInTags((*vmList)[i].Tags, tag)
		if !tagExist && resTagNotExist {
			res = append(res, (*vmList)[i])
		} else if tagExist && !resTagNotExist {
			res = append(res, (*vmList)[i])
		}
	}
	return res
}

func tagInTags(vmTags []nsx.Tag, tag string) bool {
	for _, tagOfVM := range vmTags {
		if tag == tagOfVM.Tag {
			return true
		}
	}
	return false
}

func vmsOfCondition(vmList *[]collector.VirtualMachine, cond *collector.Condition) []collector.VirtualMachine {
	var resTagNotExist bool
	if *cond.Operator == nsx.ConditionOperatorNOTEQUALS {
		resTagNotExist = true
	}
	return getVMsOfTagOrNotTag(vmList, *cond.Value, resTagNotExist)
}

func vmsOfExpr(vmList *[]collector.VirtualMachine, exp *collector.Expression) []collector.RealizedVirtualMachine {
	cond1 := (*exp)[0].(*collector.Condition)
	vmsCond1 := vmsOfCondition(vmList, cond1)
	if len(*exp) == 1 {
		return virtualToRealizedVirtual(vmsCond1)
	}
	// len(*exp) is 3
	cond2 := (*exp)[2].(*collector.Condition)
	vmsCond2 := vmsOfCondition(vmList, cond2)
	res := []collector.VirtualMachine{}
	conj := (*exp)[1].(*collector.ConjunctionOperator)
	if *conj.ConjunctionOperator.ConjunctionOperator == nsx.ConjunctionOperatorConjunctionOperatorOR {
		// union of vmsCond1 and vmsCond2
		res = append(res, vmsCond1...)
		for i := range vmsCond2 {
			if !vmInList(&res, &vmsCond2[i]) {
				res = append(res, vmsCond2[i])
			}
		}
	} else { // intersection
		for i := range vmsCond1 {
			if vmInList(&vmsCond2, &vmsCond1[i]) {
				res = append(res, vmsCond1[i])
			}
		}
	}
	return virtualToRealizedVirtual(res)
}

func vmInList(vmList *[]collector.VirtualMachine, vm *collector.VirtualMachine) bool {
	for i := range *vmList {
		if (*vmList)[i].Name() == vm.Name() {
			return true
		}
	}
	return false
}

func virtualToRealizedVirtual(origList []collector.VirtualMachine) []collector.RealizedVirtualMachine {
	res := make([]collector.RealizedVirtualMachine, len(origList))
	for i := range origList {
		realizedVM := collector.RealizedVirtualMachine{}
		realizedVM.RealizedVirtualMachine.DisplayName = origList[i].DisplayName
		realizedVM.RealizedVirtualMachine.Id = origList[i].ExternalId
		res[i] = realizedVM
	}
	return res
}
