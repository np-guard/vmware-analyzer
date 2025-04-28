package data

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
)

// Example is in s single domain
type Example struct {
	// nsx config spec fields below

	// vms details
	VMs        []string
	VMsTags    map[string][]nsx.Tag
	VMsAddress map[string]string

	// segments details
	SegmentsByVMs map[string][]string
	SegmentsBlock map[string]string

	// groups details
	GroupsByVMs         map[string][]string        // map from group name to its VMs
	GroupsByExpr        map[string]ExampleExpr     // map from group name to its expr
	GroupsOfIPAddresses map[string][]nsx.IPElement // map from group name to its ip addresses members
	GroupByPathExpr     map[string][]string        // map from group name to list of paths in the path expr
	GroupByNestedExpr   map[string]ExampleExpr     // map from group name to nexted expr def

	// dfw details
	Policies []Category

	// additional info about example, relevant for synthesis
	DisjointGroupsTags [][]string

	// JSON generation fields below
	Name string // example name for JSON file name
}

// ExamplesGeneration - main function to generate ResourcesContainerModel from specified Example object.
// It also stores the generated example in the path pkg/data/json .
//
//nolint:funlen,gocyclo // just a long function
func ExamplesGeneration(e *Example, override bool) (*collector.ResourcesContainerModel, error) {
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
	segmentedVMs := map[string]bool{}
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
			segmentedVMs[vm] = true
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
			vni := collector.VirtualNetworkInterface{
				VirtualNetworkInterface: nsx.VirtualNetworkInterface{
					LportAttachmentId: &portName,
					OwnerVmId:         &vm,
				},
			}
			if address, ok := e.VMsAddress[vm]; ok {
				vmAddress := nsx.IPAddress(address)
				vni.IpAddressInfo = []nsx.IpAddressInfo{{IpAddresses: []nsx.IPAddress{vmAddress}}}
			}
			res.VirtualNetworkInterfaceList = append(res.VirtualNetworkInterfaceList, vni)
			segment.SegmentPorts = append(segment.SegmentPorts, port)
		}
		res.SegmentList = append(res.SegmentList, segment)
	}
	// VMs might have addresses and no segment:
	for _, vmName := range e.VMs {
		if address, ok := e.VMsAddress[vmName]; ok && !segmentedVMs[vmName] {
			vni := collector.VirtualNetworkInterface{
				VirtualNetworkInterface: nsx.VirtualNetworkInterface{
					LportAttachmentId: common.PointerTo("non-relevant-port-id"),
					OwnerVmId:         &vmName,
					IpAddressInfo:     []nsx.IpAddressInfo{{IpAddresses: []nsx.IPAddress{nsx.IPAddress(address)}}},
				},
			}
			res.VirtualNetworkInterfaceList = append(res.VirtualNetworkInterfaceList, vni)
		}
	}
	// set default domain
	domainRsc := collector.Domain{}
	defaultName := "default"
	domainRsc.DisplayName = &defaultName
	res.DomainList = append(res.DomainList, domainRsc)

	// add groups
	// groups defined by VMs
	groupedVMs := []string{}

	for groupName, members := range e.GroupsByVMs {
		group := createGroupFromVMMembers(groupName, members)
		res.DomainList[0].Resources.GroupList = append(res.DomainList[0].Resources.GroupList, *group)
		groupedVMs = append(groupedVMs, members...)
	}
	// groups defined by expr and VMs
	for groupName, expr := range e.GroupsByExpr {
		group := createGroupFromExpr(groupName, &expr, res.VirtualMachineList)
		res.DomainList[0].Resources.GroupList = append(res.DomainList[0].Resources.GroupList, *group)
		groupedVMs = append(groupedVMs, common.StringifiedSliceToStrings(group.VMMembers)...)
	}
	// groups of type IPAddress
	for groupName, addresses := range e.GroupsOfIPAddresses {
		group := createGroupOfIPAddresses(groupName, addresses)
		res.DomainList[0].Resources.GroupList = append(res.DomainList[0].Resources.GroupList, *group)
		groupedVMs = append(groupedVMs, common.StringifiedSliceToStrings(group.VMMembers)...)
	}
	// groups defined by nested expr
	for groupName, expr := range e.GroupByNestedExpr {
		group := createGroupFromExpr(groupName, &expr, res.VirtualMachineList)
		res.DomainList[0].Resources.GroupList = append(res.DomainList[0].Resources.GroupList, *group)
		groupedVMs = append(groupedVMs, common.StringifiedSliceToStrings(group.VMMembers)...)
	}

	// groups defined by path expr
	for groupName, paths := range e.GroupByPathExpr {
		group := createGroupByPathExpr(groupName, paths, res, e.SegmentsByVMs)
		res.DomainList[0].Resources.GroupList = append(res.DomainList[0].Resources.GroupList, *group)
		groupedVMs = append(groupedVMs, common.StringifiedSliceToStrings(group.VMMembers)...)
	}

	nonGroupedVMs := slices.DeleteFunc(slices.Clone(e.VMs), func(vm string) bool { return slices.Contains(groupedVMs, vm) })
	if len(nonGroupedVMs) > 0 {
		group := createGroupFromVMMembers("no-group-vms-group", nonGroupedVMs)
		res.DomainList[0].Resources.GroupList = append(res.DomainList[0].Resources.GroupList, *group)
	}

	// add dfw
	res.DomainList[0].Resources.SecurityPolicyList = ToPoliciesList(e.Policies)
	res.ServiceList = getServices()

	// store the example resources object generated as JSON file
	if err := e.storeAsJSON(override, res); err != nil {
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

func createRealizedVirtualMachines(members []string) (res []collector.RealizedVirtualMachine) {
	for _, member := range members {
		res = append(res, collector.RealizedVirtualMachineFromBaseElem(
			&nsx.RealizedVirtualMachine{
				DisplayName: &member,
				Id:          &member,
			},
		))
	}
	return res
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

type ExampleNestedExpr struct {
	expr ExampleExpr
}

type ConditionIntf interface {
	toCollectorObject() collector.ExpressionElement
}

func (ne *ExampleNestedExpr) toCollectorObject() collector.ExpressionElement {
	res := &collector.NestedExpression{}
	exprs := ne.expr.exampleExprToExpr()
	res.Expressions = *exprs
	rt := nsx.NestedExpressionResourceTypeNestedExpression
	res.ResourceType = &rt
	return res
}

// ExampleExpr equiv to example_expr described above
// if op is nop then only cond1 is considered and exampleExpr is actually exampleCond; Cond2 is empty in that case
type ExampleExpr struct {
	Cond1 ConditionIntf
	Op    ExampleOp
	Cond2 ConditionIntf
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

func (cond *ExampleCond) toCollectorObject() collector.ExpressionElement {
	condKey := nsx.ConditionKeyTag
	memberType := nsx.ConditionMemberTypeVirtualMachine
	operator := nsx.ConditionOperatorEQUALS
	if cond.NotEqual {
		operator = nsx.ConditionOperatorNOTEQUALS
	}
	res := collector.Condition{Condition: nsx.Condition{Key: &condKey, MemberType: &memberType, Operator: &operator,
		Value: &cond.Tag.Tag, ResourceType: common.PointerTo(nsx.ConditionResourceTypeCondition)}}
	res.Value = &cond.Tag.Tag
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
	Scope                string
	Services             []string
	Conn                 *netset.TransportSet
	Action               string
	Direction            string // if not set, used as default with "IN_OUT"
	Description          string
}

func (r *Rule) toCollectorRule() collector.Rule {
	services, entries := calcServiceAndEntries(r.Services, r.Conn)
	scope := []string{AnyStr}
	if r.Scope != "" {
		scope = []string{r.Scope}
	}
	return collector.Rule{
		Rule: nsx.Rule{
			DisplayName:          &r.Name,
			RuleId:               &r.ID,
			Action:               (*nsx.RuleAction)(&r.Action),
			SourceGroups:         strings.Split(r.Source, common.CommaSpaceSeparator),
			DestinationGroups:    strings.Split(r.Dest, common.CommaSpaceSeparator),
			SourcesExcluded:      r.SourcesExcluded,
			DestinationsExcluded: r.DestinationsExcluded,
			Services:             services,
			Direction:            r.directionStr(),
			Scope:                scope,
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
