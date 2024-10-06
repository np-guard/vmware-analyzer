/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	rulesJSONEntry          = "rules"
	membersJSONEntry        = "members"
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
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &rule.Rule); err != nil {
		return err
	}
	if r, ok := raw[serviceEntriesJSONEntry]; ok {
		if err := json.Unmarshal(r, &rule.ServiceEntries); err != nil {
			return err
		}
	} else {
		rule.ServiceEntries = ServiceEntries{}
	}
	if r, ok := raw[firewallRuleJSONEntry]; ok {
		if err := json.Unmarshal(r, &rule.FirewallRule); err != nil {
			return err
		}
	}
	return nil
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
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &securityPolicy.SecurityPolicy); err != nil {
		return err
	}
	if r, ok := raw[rulesJSONEntry]; ok {
		if err := json.Unmarshal(r, &securityPolicy.Rules); err != nil {
			return err
		}
	}
	if r, ok := raw[defaultRuleJSONEntry]; ok {
		if err := json.Unmarshal(r, &securityPolicy.DefaultRule); err != nil {
			return err
		}
	}
	return nil
}

// /////////////////////////////////////////////////////////////////////////////////////
type IPProtocolServiceEntry struct {
	nsx.IPProtocolServiceEntry
}

const creatingConnectionError = "fail to create a connection from service %v"

func (e *IPProtocolServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type IGMPTypeServiceEntry struct {
	nsx.IGMPTypeServiceEntry
}

func (e *IGMPTypeServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type ICMPTypeServiceEntry struct {
	nsx.ICMPTypeServiceEntry
}

func (e *ICMPTypeServiceEntry) ToConnection() (*connection.Set, error) {
	if e.Protocol == nil || *e.Protocol == nsx.ICMPTypeServiceEntryProtocolICMPv6 {
		return nil, fmt.Errorf("protocol %s of ICMPTypeServiceEntry  \"%s\" is not supported", *e.Protocol, *e.DisplayName)
	}
	var tMin, tMax int64 = 0, connection.MaxICMPType
	var cMin, cMax int64 = 0, connection.MaxICMPCode
	if e.IcmpCode != nil {
		cMin = int64(*e.IcmpCode)
		cMax = cMin
	}
	if e.IcmpType != nil {
		tMin = int64(*e.IcmpType)
		tMax = tMin
	}
	return connection.ICMPConnection(tMin, tMax, cMin, cMax), nil
}

type ALGTypeServiceEntry struct {
	nsx.ALGTypeServiceEntry
}

func (e *ALGTypeServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type L4PortSetServiceEntry struct {
	nsx.L4PortSetServiceEntry
}

func (e *L4PortSetServiceEntry) ToConnection() (*connection.Set, error) {
	res := connection.None()
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
			res.Union(connection.TCPorUDPConnection(protocol, sp.min, sp.max, dp.min, dp.max))
		}
	}
	return res, nil
}

func parsePorts(ports []nsx.PortElement) ([]struct{ min, max int64 }, error) {
	res := make([]struct{ min, max int64 }, len(ports))
	if len(ports) == 0 {
		return []struct{ min, max int64 }{{connection.MinPort, connection.MaxPort}}, nil
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

func (e *EtherTypeServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type NestedServiceServiceEntry struct {
	nsx.NestedServiceServiceEntry
}

func (e *NestedServiceServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf(creatingConnectionError, *e.ResourceType)
}

type ServiceEntry interface {
	ToConnection() (*connection.Set, error)
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
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &service.Service); err != nil {
		return err
	}
	if m, ok := raw[serviceEntriesJSONEntry]; ok {
		if err := json.Unmarshal(m, &service.ServiceEntries); err != nil {
			return err
		}
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////

type VirtualMachine struct {
	nsx.VirtualMachine
}
type VirtualNetworkInterface struct {
	nsx.VirtualNetworkInterface
}
type Segment struct {
	nsx.Segment
	SegmentPorts []SegmentPort `json:"segment_ports"`
}

func (segment *Segment) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &segment.Segment); err != nil {
		return err
	}
	if m, ok := raw[segmentPortsJSONEntry]; ok {
		if err := json.Unmarshal(m, &segment.SegmentPorts); err != nil {
			return err
		}
	}
	return nil
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

type ExpressionElement interface {
	expressionElementIsMe()
}

type Condition struct {
	nsx.Condition
}

func (Condition) expressionElementIsMe() {}

type ConjunctionOperator struct {
	nsx.ConjunctionOperator
}

func (ConjunctionOperator) expressionElementIsMe() {}

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
	Members    []RealizedVirtualMachine `json:"members"`
	Expression Expression               `json:"expression"`
}

func (group *Group) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &group.Group); err != nil {
		return err
	}
	if err := unmarshalFromRaw(raw, membersJSONEntry, &group.Members); err != nil {
		return err
	}
	if err := unmarshalFromRaw(raw, expressionJSONEntry, &group.Expression); err != nil {
		return err
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////

type Domain struct {
	nsx.Domain
	Resources DomainResources `json:"resources"`
}

func (domain *Domain) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &domain.Domain); err != nil {
		return err
	}
	if m, ok := raw[resourcesJSONEntry]; ok {
		if err := json.Unmarshal(m, &domain.Resources); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalFromRaw[a any](raw map[string]json.RawMessage, entry string, res *a) error {
	if m, ok := raw[entry]; ok {
		if err := json.Unmarshal(m, res); err != nil {
			return err
		}
	}
	return nil
}
