/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	rulesJSONEntry          = "rules"
	membersJSONEntry        = "vm_members"
	vifMembersJSONEntry     = "vfi_members"
	addressMembersJSONEntry = "address_members"
	expressionJSONEntry     = "expression"
	resourcesJSONEntry      = "resources"
	serviceEntriesJSONEntry = "service_entries"
	resourceTypeJSONEntry   = "resource_type"
	defaultRuleJSONEntry    = "default_rule"
	firewallRuleJSONEntry   = "firewall_rule"
	segmentPortsJSONEntry   = "segment_ports"
)

type Rule struct {
	nsx.Rule
	FirewallRule   FirewallRule   `json:"firewall_rule"`
	ServiceEntries ServiceEntries `json:"service_entries"`
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
	Rules       []Rule        `json:"rules"`
	DefaultRule *FirewallRule `json:"default_rule"`
}

func (securityPolicy *SecurityPolicy) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd2Fields(b, &securityPolicy.SecurityPolicy,
		rulesJSONEntry, &securityPolicy.Rules,
		defaultRuleJSONEntry, &securityPolicy.DefaultRule)
}

// /////////////////////////////////////////////////////////////////////////////////////
type GatewayPolicy struct {
	nsx.GatewayPolicy
	Rules []Rule `json:"rules"`
}

func (gatewayPolicy *GatewayPolicy) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &gatewayPolicy.GatewayPolicy,
		rulesJSONEntry, &gatewayPolicy.Rules)
}

// /////////////////////////////////////////////////////////////////////////////////////
type IPProtocolServiceEntry struct {
	nsx.IPProtocolServiceEntry
}

const creatingConnectionError = "fail to create a connection from service %v"

func (e *IPProtocolServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type IGMPTypeServiceEntry struct {
	nsx.IGMPTypeServiceEntry
}

func (e *IGMPTypeServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type ICMPTypeServiceEntry struct {
	nsx.ICMPTypeServiceEntry
}

func (e *ICMPTypeServiceEntry) ToConnection() (*netset.TransportSet, error) {
	if e.Protocol == nil || *e.Protocol == nsx.ICMPTypeServiceEntryProtocolICMPv6 {
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

func (e *ALGTypeServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type L4PortSetServiceEntry struct {
	nsx.L4PortSetServiceEntry
}

func (e *L4PortSetServiceEntry) ToConnection() (*netset.TransportSet, error) {
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

func (e *EtherTypeServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type NestedServiceServiceEntry struct {
	nsx.NestedServiceServiceEntry
}

func (e *NestedServiceServiceEntry) ToConnection() (*netset.TransportSet, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type ServiceEntry interface {
	ToConnection() (*netset.TransportSet, error)
}

type ServiceEntries []ServiceEntry

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
	ServiceEntries ServiceEntries `json:"service_entries"`
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
	SegmentPorts []SegmentPort `json:"segment_ports"`
}

func (segment *Segment) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd1Field(b, &segment.Segment, segmentPortsJSONEntry, &segment.SegmentPorts)
}

type SegmentPort struct {
	nsx.SegmentPort
}

type Tier0 struct {
	nsx.Tier0
}
type Tier1 struct {
	nsx.Tier1
}

type RealizedVirtualMachine struct {
	nsx.RealizedVirtualMachine
}

///////////////////////////////////////////////////////////////////////////////////////

type ExpressionElement interface{}

type Condition struct {
	nsx.Condition
}

type ConjunctionOperator struct {
	nsx.ConjunctionOperator
}
type NestedExpression struct {
	nsx.NestedExpression
}
type IPAddressExpression struct {
	nsx.IPAddressExpression
}
type MACAddressExpression struct {
	nsx.MACAddressExpression
}
type ExternalIDExpression struct {
	nsx.ExternalIDExpression
}
type PathExpression struct {
	nsx.PathExpression
}
type IdentityGroupExpression struct {
	nsx.IdentityGroupExpression
}
type Expression []ExpressionElement

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
		case "Condition":
			res = &Condition{}
		case "ConjunctionOperator":
			res = &ConjunctionOperator{}
		case "NestedExpression":
			res = &NestedExpression{}
		case "IPAddressExpression":
			res = &IPAddressExpression{}
		case "MACAddressExpression":
			res = &MACAddressExpression{}
		case "ExternalIDExpression":
			res = &ExternalIDExpression{}
		case "PathExpression":
			res = &PathExpression{}
		case "IdentityGroupExpression":
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
	VMMembers      []RealizedVirtualMachine  `json:"vm_members"`
	VIFMembers     []VirtualNetworkInterface `json:"vif_members"`
	AddressMembers []nsx.IPElement           `json:"ips_members"`
	Expression     Expression                `json:"expression"`
}

func (group *Group) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAnd4Fields(b, &group.Group,
		membersJSONEntry, &group.VMMembers,
		vifMembersJSONEntry, &group.VIFMembers,
		addressMembersJSONEntry, &group.AddressMembers,
		expressionJSONEntry, &group.Expression,
	)
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
	return nil
}
