/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

const (
	rulesJSONEntry                 = "rules"
	membersJSONEntry               = "vm_members"
	vifMembersJSONEntry            = "vif_members"
	addressMembersJSONEntry        = "ips_members"
	segmentMembersJSONEntry        = "segment_members"
	segmentPortMembersJSONEntry    = "segment_port_members"
	transpoertNodeMembersJSONEntry = "transport_node_members"
	ipGroupMembersJSONEntry        = "ip_group_members"
	expressionJSONEntry            = "expression"
	expressionsJSONEntry           = "expressions"
	resourcesJSONEntry             = "resources"
	serviceEntriesJSONEntry        = "service_entries"
	resourceTypeJSONEntry          = "resource_type"
	defaultRuleJSONEntry           = "default_rule"
	firewallRuleJSONEntry          = "firewall_rule"
	segmentPortsJSONEntry          = "segment_ports"
	policyNatsJSONEntry            = "policy_nats"
)

type Rule struct {
	nsx.Rule
	FirewallRule   *FirewallRule  `json:"firewall_rule,omitempty"`
	ServiceEntries ServiceEntries `json:"service_entries,omitempty"`
}

func (rule *Rule) UnmarshalJSON(b []byte) error {
	rule.ServiceEntries = ServiceEntries{}
	return UnmarshalBaseStructAnd2Fields(b, &rule.Rule,
		serviceEntriesJSONEntry, &rule.ServiceEntries,
		firewallRuleJSONEntry, &rule.FirewallRule)
}

type FirewallRule struct {
	nsx.FirewallRule
}

type SecurityPolicy struct {
	nsx.SecurityPolicy
	Rules       []Rule        `json:"rules,omitempty"`
	DefaultRule *FirewallRule `json:"default_rule,omitempty"`
}

func (securityPolicy *SecurityPolicy) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd2Fields(b, &securityPolicy.SecurityPolicy,
		rulesJSONEntry, &securityPolicy.Rules,
		defaultRuleJSONEntry, &securityPolicy.DefaultRule)
}

// /////////////////////////////////////////////////////////////////////////////////////
type GatewayPolicy struct {
	nsx.GatewayPolicy
	Rules []Rule `json:"rules,omitempty"`
}

func (gatewayPolicy *GatewayPolicy) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &gatewayPolicy.GatewayPolicy,
		rulesJSONEntry, &gatewayPolicy.Rules)
}

// /////////////////////////////////////////////////////////////////////////////////////
type RedirectionPolicy struct {
	nsx.RedirectionPolicy
	RedirectionRules []RedirectionRule `json:"rules,omitempty"`
}

func (redirectionPolicy *RedirectionPolicy) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &redirectionPolicy.RedirectionPolicy,
		rulesJSONEntry, &redirectionPolicy.RedirectionRules)
}

type RedirectionRule struct {
	nsx.RedirectionRule
	ServiceEntries ServiceEntries `json:"service_entries,omitempty"`
}

func (rule *RedirectionRule) UnmarshalJSON(b []byte) error {
	rule.ServiceEntries = ServiceEntries{}
	return UnmarshalBaseStructAnd1Field(b, &rule.RedirectionRule,
		serviceEntriesJSONEntry, &rule.ServiceEntries)
}

// /////////////////////////////////////////////////////////////////////////////////////
type IPProtocolServiceEntry struct {
	nsx.IPProtocolServiceEntry
}

func (e *IPProtocolServiceEntry) String() string {
	return serviceEntryStr(nsx.IPProtocolServiceEntryResourceTypeIPProtocolServiceEntry, *e.DisplayName)
}

func (e *IPProtocolServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(common.ErrCreatingConnection, *e.ResourceType)
}

type IGMPTypeServiceEntry struct {
	nsx.IGMPTypeServiceEntry
}

func (e *IGMPTypeServiceEntry) String() string {
	return serviceEntryStr(nsx.IPProtocolServiceEntryResourceTypeIGMPTypeServiceEntry, *e.DisplayName)
}

func (e *IGMPTypeServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(common.ErrCreatingConnection, *e.ResourceType)
}

type ICMPTypeServiceEntry struct {
	nsx.ICMPTypeServiceEntry
}

func (e *ICMPTypeServiceEntry) String() string {
	nameAndProtocol := common.JoinNonNilStrings([]*string{e.DisplayName, (*string)(e.Protocol)}, common.CommaSeparator)
	// todo: add icmp type and code to str details
	return serviceEntryStr(nsx.IPProtocolServiceEntryResourceTypeICMPTypeServiceEntry, nameAndProtocol)
}

func (e *ICMPTypeServiceEntry) ToConnection() (*netset.TransportSet, error) {
	if e.Protocol != nil && *e.Protocol == nsx.ICMPTypeServiceEntryProtocolICMPv6 {
		return nil, fmt.Errorf("protocol %s of ICMPTypeServiceEntry  \"%s\" is not supported", *e.Protocol, *e.DisplayName)
	}
	var tMin, tMax int64 = 0, int64(netp.MaxICMPType)
	var cMin, cMax int64 = 0, int64(netp.MaxICMPCode)
	if e.IcmpCode != nil {
		cMin = int64(*e.IcmpCode)
		cMax = cMin
	}
	if e.IcmpType != nil {
		tMin = int64(*e.IcmpType)
		tMax = tMin
	}
	return netset.NewICMPTransport(tMin, tMax, cMin, cMax), nil
}

type ALGTypeServiceEntry struct {
	nsx.ALGTypeServiceEntry
}

func (e *ALGTypeServiceEntry) String() string {
	return serviceEntryStr(nsx.IPProtocolServiceEntryResourceTypeALGTypeServiceEntry, *e.DisplayName)
}

func (e *ALGTypeServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(common.ErrCreatingConnection, *e.ResourceType)
}

type L4PortSetServiceEntry struct {
	nsx.L4PortSetServiceEntry
}

func serviceEntryStr(kind nsx.IPProtocolServiceEntryResourceType, name string) string {
	return fmt.Sprintf("[%s]%s", kind, name)
}

func (e *L4PortSetServiceEntry) String() string {
	nameAndProtocol := common.JoinNonNilStrings([]*string{e.DisplayName, (*string)(e.L4Protocol)}, common.CommaSeparator)
	var portElementStr = func(s nsx.PortElement) string { return string(s) }
	srcPortStr := "SourcePorts: " + common.JoinCustomStrFuncSlice(e.SourcePorts, portElementStr, common.CommaSeparator)
	dstPortsStr := "DestinationPorts: " + common.JoinCustomStrFuncSlice(e.DestinationPorts, portElementStr, common.CommaSeparator)
	allDetails := strings.Join([]string{nameAndProtocol, srcPortStr, dstPortsStr}, common.CommaSeparator)
	return serviceEntryStr(nsx.IPProtocolServiceEntryResourceTypeL4PortSetServiceEntry, allDetails)
}

func (e *L4PortSetServiceEntry) ToConnection() (*netset.TransportSet, error) {
	if e.L4Protocol == nil {
		return nil, fmt.Errorf("L4PortSetServiceEntry object has nil L4Protocol")
	}
	res := netset.NoTransports()
	protocol := netp.ProtocolString(*e.L4Protocol)
	srcPorts, err := parsePorts(e.SourcePorts)
	if err != nil {
		return nil, err
	}
	dstPorts, err := parsePorts(e.DestinationPorts)
	if err != nil {
		return nil, err
	}
	for _, sp := range srcPorts {
		for _, dp := range dstPorts {
			res = res.Union(netset.NewTCPorUDPTransport(protocol, sp.min, sp.max, dp.min, dp.max))
		}
	}
	return res, nil
}

func parsePorts(ports []nsx.PortElement) ([]struct{ min, max int64 }, error) {
	res := make([]struct{ min, max int64 }, len(ports))
	if len(ports) == 0 {
		return []struct{ min, max int64 }{{netp.MinPort, netp.MaxPort}}, nil
	}
	for i, portString := range ports {
		var err error
		if strings.Contains(string(portString), "-") {
			_, err = fmt.Sscanf(string(portString), "%d-%d", &res[i].min, &res[i].max)
		} else {
			_, err = fmt.Sscanf(string(portString), "%d", &res[i].min)
			res[i].max = res[i].min
		}
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

type EtherTypeServiceEntry struct {
	nsx.EtherTypeServiceEntry
}

func (e *EtherTypeServiceEntry) String() string {
	return serviceEntryStr(nsx.IPProtocolServiceEntryResourceTypeEtherTypeServiceEntry, *e.DisplayName)
}

func (e *EtherTypeServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(common.ErrCreatingConnection, *e.ResourceType)
}

type NestedServiceServiceEntry struct {
	nsx.NestedServiceServiceEntry
}

func (e *NestedServiceServiceEntry) String() string {
	return serviceEntryStr(nsx.IPProtocolServiceEntryResourceTypeNestedServiceServiceEntry, *e.DisplayName)
}

func (e *NestedServiceServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(common.ErrCreatingConnection, *e.ResourceType)
}

type ServiceEntry interface {
	ToConnection() (*netset.TransportSet, error)
	String() string
}

type ServiceEntries []ServiceEntry

func (s *ServiceEntries) MarshalJSON() ([]byte, error) {
	type ServiceEntriesPlain ServiceEntries
	for _, e := range *s {
		switch v := e.(type) {
		case *ALGTypeServiceEntry:
			v.ResourceType = common.PointerTo(nsx.ALGTypeServiceEntryResourceTypeALGTypeServiceEntry)
		case *EtherTypeServiceEntry:
			v.ResourceType = common.PointerTo(nsx.EtherTypeServiceEntryResourceTypeEtherTypeServiceEntry)
		case *ICMPTypeServiceEntry:
			v.ResourceType = common.PointerTo(nsx.ICMPTypeServiceEntryResourceTypeICMPTypeServiceEntry)
		case *IGMPTypeServiceEntry:
			v.ResourceType = common.PointerTo(nsx.IGMPTypeServiceEntryResourceTypeIGMPTypeServiceEntry)
		case *IPProtocolServiceEntry:
			v.ResourceType = common.PointerTo(nsx.IPProtocolServiceEntryResourceTypeIPProtocolServiceEntry)
		case *L4PortSetServiceEntry:
			v.ResourceType = common.PointerTo(nsx.L4PortSetServiceEntryResourceTypeL4PortSetServiceEntry)
		case *NestedServiceServiceEntry:
			v.ResourceType = common.PointerTo(nsx.NestedServiceServiceEntryResourceTypeNestedServiceServiceEntry)
		}
	}
	sp := ServiceEntriesPlain(*s)
	return json.Marshal(sp)
}

func (s *ServiceEntries) UnmarshalJSON(b []byte) error {
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return err
	}
	*s = make([]ServiceEntry, len(raws))
	for i, rawMessage := range raws {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rawMessage, &raw); err != nil {
			return err
		}
		var cType string
		if err := json.Unmarshal(raw[resourceTypeJSONEntry], &cType); err != nil {
			return err
		}
		var res ServiceEntry
		switch cType {
		case "IPProtocolServiceEntry":
			res = &IPProtocolServiceEntry{}
		case "IGMPTypeServiceEntry":
			res = &IGMPTypeServiceEntry{}
		case "ICMPTypeServiceEntry":
			res = &ICMPTypeServiceEntry{}
		case "ALGTypeServiceEntry":
			res = &ALGTypeServiceEntry{}
		case "L4PortSetServiceEntry":
			res = &L4PortSetServiceEntry{}
		case "EtherTypeServiceEntry":
			res = &EtherTypeServiceEntry{}
		case "NestedServiceServiceEntry":
			res = &NestedServiceServiceEntry{}
		default:
			return fmt.Errorf("fail to unmarshal entry %s", rawMessage)
		}
		if err := json.Unmarshal(rawMessage, res); err != nil {
			return err
		}
		(*s)[i] = res
	}
	return nil
}

type Service struct {
	nsx.Service
	ServiceEntries ServiceEntries `json:"service_entries,omitempty"`
}

func (service *Service) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &service.Service, serviceEntriesJSONEntry, &service.ServiceEntries)
}

///////////////////////////////////////////////////////////////////////////////////////

type VirtualMachine struct {
	nsx.VirtualMachine
}
type VirtualNetworkInterface struct {
	nsx.VirtualNetworkInterface
}

func (vni *VirtualNetworkInterface) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	// for some reason, the values of the following entries has a prefix that should be removed:
	entriesToFix := [][]string{
		{"owner_vm_type", "VIRTUAL_MACHINE_TYPE_"},
		{"ip_address_info", "IP_ADDRESS_SOURCE_TYPE_"},
	}
	for _, entryToFix := range entriesToFix {
		if v, ok := raw[entryToFix[0]]; ok {
			if strings.Contains(string(v), entryToFix[1]) {
				raw[entryToFix[0]] = json.RawMessage(strings.ReplaceAll(string(v), entryToFix[1], ""))
			}
		}
	}
	fixedBytes, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return vni.VirtualNetworkInterface.UnmarshalJSON(fixedBytes)
}

type Segment struct {
	nsx.Segment
	SegmentPorts []SegmentPort `json:"segment_ports,omitempty"`
}

func (segment *Segment) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &segment.Segment, segmentPortsJSONEntry, &segment.SegmentPorts)
}

type SegmentPort struct {
	nsx.SegmentPort
}

type Tier0 struct {
	nsx.Tier0
	PolicyNats []PolicyNat `json:"policy_nats,omitempty"`
}

func (t0 *Tier0) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &t0.Tier0, policyNatsJSONEntry, &t0.PolicyNats)
}

type Tier1 struct {
	nsx.Tier1
	PolicyNats []PolicyNat `json:"policy_nats,omitempty"`
}

func (t1 *Tier1) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &t1.Tier1, policyNatsJSONEntry, &t1.PolicyNats)
}

type PolicyNat struct {
	nsx.PolicyNat
	Rules []PolicyNatRule `json:"rules,omitempty"`
}

func (policyNat *PolicyNat) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &policyNat.PolicyNat, rulesJSONEntry, &policyNat.Rules)
}

type PolicyNatRule struct {
	nsx.PolicyNatRule
}

type RealizedVirtualMachine struct {
	nsx.RealizedVirtualMachine
}

func (r RealizedVirtualMachine) String() string {
	return *r.DisplayName
}

func RealizedVirtualMachineFromBaseElem(base *nsx.RealizedVirtualMachine) RealizedVirtualMachine {
	res := RealizedVirtualMachine{}
	res.RealizedVirtualMachine = *base
	return res
}

///////////////////////////////////////////////////////////////////////////////////////

func addParentheses(s []string) string { return fmt.Sprintf("(%s)", strings.Join(s, common.Space)) }

type ExpressionElement interface {
	String() string
}

type Condition struct {
	nsx.Condition
}

func (e *Condition) String() string {
	s := []string{
		string(*e.Key),
		"Of",
		string(*e.MemberType),
		string(*e.Operator),
		*e.Value,
	}
	return addParentheses(s)
}

type ConjunctionOperator struct {
	nsx.ConjunctionOperator
}

func (e *ConjunctionOperator) String() string {
	return string(*e.ConjunctionOperator.ConjunctionOperator)
}

type NestedExpression struct {
	nsx.NestedExpression
	Expressions Expression `json:"expressions"`
}

var toImplementFunc = func(exprKind string) string {
	return fmt.Sprintf("(String() not yet implemented for %s expression element)", exprKind)
}

func (e *NestedExpression) String() string {
	exprStr := make([]string, len(e.Expressions))
	for i, subExpr := range e.Expressions {
		if i%2 == 0 {
			exprStr[i] = "(" + subExpr.String() + ")"
		} else {
			exprStr[i] = subExpr.String()
		}
	}
	return strings.Join(exprStr, common.Space)
}

type IPAddressExpression struct {
	nsx.IPAddressExpression
}

func (e *IPAddressExpression) String() string {
	return common.JoinCustomStrFuncSlice(e.IpAddresses,
		func(a nsx.IPElement) string { return string(a) },
		common.CommaSpaceSeparator)
}

type MACAddressExpression struct {
	nsx.MACAddressExpression
}

func (e *MACAddressExpression) String() string {
	return toImplementFunc(string(nsx.IdentityGroupExpressionResourceTypeMACAddressExpression))
} // todo

type ExternalIDExpression struct {
	nsx.ExternalIDExpression
}

func (e *ExternalIDExpression) String() string {
	return addParentheses(append([]string{"( members IDs: "}, e.ExternalIds...))
}

type PathExpression struct {
	nsx.PathExpression
}

func (e *PathExpression) String() string {
	return strings.Join(e.Paths, common.CommaSpaceSeparator)
}

type IdentityGroupExpression struct {
	nsx.IdentityGroupExpression
}

func (e *IdentityGroupExpression) String() string {
	return toImplementFunc(string(nsx.IdentityGroupExpressionResourceTypeIdentityGroupExpression))
} // todo

type Expression []ExpressionElement

func (e *Expression) String() string {
	elementsStrings := make([]string, len(*e))
	for i, el := range *e {
		elementsStrings[i] = el.String()
	}
	return addParentheses(elementsStrings)
}

func unmarshalNestedExpression(expressionsContent json.RawMessage) (*Expression, error) {
	var rawEntries []json.RawMessage
	if err := json.Unmarshal(expressionsContent, &rawEntries); err != nil {
		return nil, err
	}
	nestedExprRes := make([]ExpressionElement, len(rawEntries))
	var newResExpr Expression = nestedExprRes
	newResExprPtr := &newResExpr
	if err := newResExprPtr.UnmarshalJSON(expressionsContent); err != nil {
		return nil, err
	}
	return newResExprPtr, nil
}

func (e *Expression) UnmarshalJSON(b []byte) error {
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return err
	}
	*e = make([]ExpressionElement, len(raws))
	for i, rawMessage := range raws {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rawMessage, &raw); err != nil {
			return err
		}
		var cType string
		if err := json.Unmarshal(raw[resourceTypeJSONEntry], &cType); err != nil {
			return err
		}
		var res ExpressionElement
		switch cType {
		case string(nsx.IdentityGroupExpressionResourceTypeCondition):
			res = &Condition{}
		case string(nsx.IdentityGroupExpressionResourceTypeConjunctionOperator):
			res = &ConjunctionOperator{}
		case string(nsx.IdentityGroupExpressionResourceTypeNestedExpression):
			nestedExpr, err := unmarshalNestedExpression(raw[expressionsJSONEntry])
			if err != nil {
				return err
			}
			res = &NestedExpression{
				Expressions: *nestedExpr,
			}
		case string(nsx.IdentityGroupExpressionResourceTypeIPAddressExpression):
			res = &IPAddressExpression{}
		case string(nsx.IdentityGroupExpressionResourceTypeMACAddressExpression):
			res = &MACAddressExpression{}
		case string(nsx.IdentityGroupExpressionResourceTypeExternalIDExpression):
			res = &ExternalIDExpression{}
		case string(nsx.IdentityGroupExpressionResourceTypePathExpression):
			res = &PathExpression{}
		case string(nsx.IdentityGroupExpressionResourceTypeIdentityGroupExpression):
			res = &IdentityGroupExpression{}

		default:
			return fmt.Errorf("fail to unmarshal expression %s", rawMessage)
		}
		if err := json.Unmarshal(rawMessage, &res); err != nil {
			return err
		}
		(*e)[i] = res
	}
	return nil
}

type Group struct {
	nsx.Group
	VMMembers      []RealizedVirtualMachine       `json:"vm_members,omitempty"`
	VIFMembers     []VirtualNetworkInterface      `json:"vif_members,omitempty"`
	AddressMembers []nsx.IPElement                `json:"ips_members,omitempty"`
	Segments       []nsx.PolicyGroupMemberDetails `json:"segment_members,omitempty"`
	SegmentPorts   []nsx.PolicyGroupMemberDetails `json:"segment_port_members,omitempty"`
	IPGroups       []nsx.PolicyGroupMemberDetails `json:"ip_group_members,omitempty"`
	TransportNodes []nsx.PolicyGroupMemberDetails `json:"transport_node_members,omitempty"`

	Expression Expression `json:"expression,omitempty"`
}

func (group *Group) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd8Fields(b, &group.Group,
		membersJSONEntry, &group.VMMembers,
		vifMembersJSONEntry, &group.VIFMembers,
		addressMembersJSONEntry, &group.AddressMembers,
		segmentMembersJSONEntry, &group.Segments,
		segmentPortMembersJSONEntry, &group.SegmentPorts,
		ipGroupMembersJSONEntry, &group.IPGroups,
		transpoertNodeMembersJSONEntry, &group.TransportNodes,
		expressionJSONEntry, &group.Expression,
	)
}

func (group *Group) IsGroupTypeIPAddress() bool {
	return slices.Contains(group.GroupType, nsx.GroupTypesIPAddress)
}

func (group *Group) AddressMembersStrings() []string {
	return common.CustomStrSliceToStrings(group.AddressMembers, func(ip nsx.IPElement) string { return string(ip) })
}

func (group *Group) Name() string {
	if group.DisplayName == nil {
		return ""
	}
	return *group.DisplayName
}

func (group *Group) String() string {
	return group.Name()
}

func (group *Group) Description() string {
	switch {
	case len(group.Expression) != 0:
		return group.Expression.String()
	case group.DisplayName != nil:
		return *group.DisplayName
	default:
		return *group.Id
	}
}

///////////////////////////////////////////////////////////////////////////////////////

type Domain struct {
	nsx.Domain
	Resources DomainResources `json:"resources"`
}

func (domain *Domain) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &domain.Domain, resourcesJSONEntry, &domain.Resources)
}

// ///////////////////////////////////////////////////////////////////////////////////////
func unmarshalFromRaw[t any](raw map[string]json.RawMessage, entry string, res *t) error {
	if m, ok := raw[entry]; ok {
		if err := json.Unmarshal(m, res); err != nil {
			return err
		}
	}
	return nil
}

var nilWithType *struct{}

func UnmarshalBaseStructAnd1Field[baseType any, fieldType1 any](
	b []byte, base *baseType,
	entry1 string, field1 *fieldType1,
) error {
	return UnmarshalBaseStructAnd4Fields(b, base, entry1, field1, "", nilWithType, "", nilWithType, "", nilWithType)
}

func Unmarshal2Fields[fieldType1 any, fieldType2 any](
	b []byte,
	entry1 string, field1 *fieldType1,
	entry2 string, field2 *fieldType2,
) error {
	return UnmarshalBaseStructAnd4Fields(b, nilWithType, entry1, field1, entry2, field2, "", nilWithType, "", nilWithType)
}
func UnmarshalBaseStructAnd2Fields[baseType any, fieldType1 any, fieldType2 any](
	b []byte, base *baseType,
	entry1 string, field1 *fieldType1,
	entry2 string, field2 *fieldType2,
) error {
	return UnmarshalBaseStructAnd4Fields(b, base, entry1, field1, entry2, field2, "", nilWithType, "", nilWithType)
}

func UnmarshalBaseStructAnd4Fields[baseType any, fieldType1 any, fieldType2 any, fieldType3 any, fieldType4 any](
	b []byte, base *baseType,
	entry1 string, field1 *fieldType1,
	entry2 string, field2 *fieldType2,
	entry3 string, field3 *fieldType3,
	entry4 string, field4 *fieldType4,
) error {
	return UnmarshalBaseStructAnd8Fields(b, base, entry1, field1, entry2, field2, entry3, field3, entry4, field4,
		"", nilWithType, "", nilWithType, "", nilWithType, "", nilWithType)
}

//nolint:gocyclo // just a long function
func UnmarshalBaseStructAnd8Fields[baseType any,
	fieldType1 any, fieldType2 any,
	fieldType3 any, fieldType4 any,
	fieldType5 any, fieldType6 any,
	fieldType7 any, fieldType8 any](
	b []byte, base *baseType,
	entry1 string, field1 *fieldType1,
	entry2 string, field2 *fieldType2,
	entry3 string, field3 *fieldType3,
	entry4 string, field4 *fieldType4,
	entry5 string, field5 *fieldType5,
	entry6 string, field6 *fieldType6,
	entry7 string, field7 *fieldType7,
	entry8 string, field8 *fieldType8,
) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if base != nil {
		if err := json.Unmarshal(b, base); err != nil {
			return err
		}
	}
	if field1 != nil {
		if err := unmarshalFromRaw(raw, entry1, field1); err != nil {
			return err
		}
	}
	if field2 != nil {
		if err := unmarshalFromRaw(raw, entry2, field2); err != nil {
			return err
		}
	}
	if field3 != nil {
		if err := unmarshalFromRaw(raw, entry3, field3); err != nil {
			return err
		}
	}
	if field4 != nil {
		if err := unmarshalFromRaw(raw, entry4, field4); err != nil {
			return err
		}
	}
	if field5 != nil {
		if err := unmarshalFromRaw(raw, entry5, field5); err != nil {
			return err
		}
	}
	if field6 != nil {
		if err := unmarshalFromRaw(raw, entry6, field6); err != nil {
			return err
		}
	}
	if field7 != nil {
		if err := unmarshalFromRaw(raw, entry7, field7); err != nil {
			return err
		}
	}
	if field8 != nil {
		if err := unmarshalFromRaw(raw, entry8, field8); err != nil {
			return err
		}
	}
	return nil
}
