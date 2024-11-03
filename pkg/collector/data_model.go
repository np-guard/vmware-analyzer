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
	membersJSONEntry        = "members"
	expressionJSONEntry     = "expression"
	resourcesJSONEntry      = "resources"
	serviceEntriesJSONEntry = "service_entries"
	resourceTypeJSONEntry   = "resource_type"
	defaultRuleJSONEntry    = "default_rule"
	firewallRuleJSONEntry   = "firewall_rule"
	segmentPortsJSONEntry   = "segment_ports"
)

var nilWithType *struct{}

type Rule struct {
	nsx.Rule
	FirewallRule   FirewallRule   `json:"firewall_rule"`
	ServiceEntries ServiceEntries `json:"service_entries"`
}

func (rule *Rule) UnmarshalJSON(b []byte) error {
	rule.ServiceEntries = ServiceEntries{}
	return UnmarshalBaseStructAndFields(b, &rule.Rule,
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
	return UnmarshalBaseStructAndFields(b, &securityPolicy.SecurityPolicy,
		rulesJSONEntry, &securityPolicy.Rules,
		defaultRuleJSONEntry, &securityPolicy.DefaultRule)
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
	return UnmarshalBaseStructAndFields(b, &service.Service, serviceEntriesJSONEntry, &service.ServiceEntries, "", nilWithType)
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
	return UnmarshalBaseStructAndFields(b, &segment.Segment, segmentPortsJSONEntry, &segment.SegmentPorts, "", nilWithType)
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
	return UnmarshalBaseStructAndFields(b, &group.Group, membersJSONEntry, &group.Members, expressionJSONEntry, &group.Expression)
}

///////////////////////////////////////////////////////////////////////////////////////

type Domain struct {
	nsx.Domain
	Resources DomainResources `json:"resources"`
}

func (domain *Domain) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAndFields(b, &domain.Domain, resourcesJSONEntry, &domain.Resources, "", nilWithType)
}

// ///////////////////////////////////////////////////////////////////////////////////////
type TraceflowConfig struct {
	// Configuration of packet data
	Packet *nsx.FieldsPacketData `json:"packet,omitempty" yaml:"packet,omitempty" mapstructure:"packet,omitempty"`
	// Policy path or UUID (validated for syntax only) of segment port to start
	// traceflow from. Auto-plumbed ports don't have corresponding policy path. Both
	// overlay backed port and VLAN backed port are supported.
	SourceId *string `json:"source_id,omitempty" yaml:"source_id,omitempty" mapstructure:"source_id,omitempty"`
}

func (config *TraceflowConfig) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAndFields(b, nilWithType, "packet", &config.Packet, "source_id", &config.SourceId)
}

///////////////////////////////////////////////////////////////////////////////////////

type TraceFlowObservationElement interface{}

type PolicyTraceflowObservationDelivered struct {
	nsx.PolicyTraceflowObservationDelivered
}
type PolicyTraceflowObservationDropped struct {
	nsx.PolicyTraceflowObservationDropped
}
type PolicyTraceflowObservationDroppedLogical struct {
	nsx.PolicyTraceflowObservationDroppedLogical
}
type PolicyTraceflowObservationForwardedLogical struct {
	nsx.PolicyTraceflowObservationForwardedLogical
}
type PolicyTraceflowObservationReceivedLogical struct {
	nsx.PolicyTraceflowObservationReceivedLogical
}
type PolicyTraceflowObservationRelayedLogical struct {
	nsx.PolicyTraceflowObservationRelayedLogical
}
type TraceflowObservationDelivered struct {
	nsx.TraceflowObservationDelivered
}
type TraceflowObservationDropped struct {
	nsx.TraceflowObservationDropped
}
type TraceflowObservationDroppedLogical struct {
	nsx.TraceflowObservationDroppedLogical
}
type TraceflowObservationForwarded struct {
	nsx.TraceflowObservationForwarded
}
type TraceflowObservationForwardedLogical struct {
	nsx.TraceflowObservationForwardedLogical
}
type TraceflowObservationProtected struct {
	nsx.TraceflowObservationProtected
}
type TraceflowObservationReceived struct {
	nsx.TraceflowObservationReceived
}
type TraceflowObservationReceivedLogical struct {
	nsx.TraceflowObservationReceivedLogical
}
type TraceflowObservationRelayedLogical struct {
	nsx.TraceflowObservationRelayedLogical
}
type TraceflowObservationReplicationLogical struct {
	nsx.TraceflowObservationReplicationLogical
}

type TraceFlowObservations []TraceFlowObservationElement

func (e *TraceFlowObservations) UnmarshalJSON(b []byte) error {
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return err
	}
	*e = make([]TraceFlowObservationElement, len(raws))
	for i, rawMessage := range raws {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rawMessage, &raw); err != nil {
			return err
		}
		var cType string
		if err := json.Unmarshal(raw[resourceTypeJSONEntry], &cType); err != nil {
			return err
		}
		var res TraceFlowObservationElement
		switch cType {
		case "PolicyTraceflowObservationDelivered":
			res = &PolicyTraceflowObservationDelivered{}
		case "PolicyTraceflowObservationDropped":
			res = &PolicyTraceflowObservationDropped{}
		case "PolicyTraceflowObservationDroppedLogical":
			res = &PolicyTraceflowObservationDroppedLogical{}
		case "PolicyTraceflowObservationForwardedLogical":
			res = &PolicyTraceflowObservationForwardedLogical{}
		case "PolicyTraceflowObservationReceivedLogical":
			res = &PolicyTraceflowObservationReceivedLogical{}
		case "PolicyTraceflowObservationRelayedLogical":
			res = &PolicyTraceflowObservationRelayedLogical{}
		case "TraceflowObservationDelivered":
			res = &TraceflowObservationDelivered{}
		case "TraceflowObservationDropped":
			res = &TraceflowObservationDropped{}
		case "TraceflowObservationDroppedLogical":
			res = &TraceflowObservationDroppedLogical{}
		case "TraceflowObservationForwarded":
			res = &TraceflowObservationForwarded{}
		case "TraceflowObservationForwardedLogical":
			res = &TraceflowObservationForwardedLogical{}
		case "TraceflowObservationProtected":
			res = &TraceflowObservationProtected{}
		case "TraceflowObservationReceived":
			res = &TraceflowObservationReceived{}
		case "TraceflowObservationReceivedLogical":
			res = &TraceflowObservationReceivedLogical{}
		case "TraceflowObservationRelayedLogical":
			res = &TraceflowObservationRelayedLogical{}
		case "TraceflowObservationReplicationLogical":
			res = &TraceflowObservationReplicationLogical{}
			default:
				return fmt.Errorf("fail to unmarshal TraceFlowObservations %s", rawMessage)
		}
		if err := json.Unmarshal(rawMessage, &res); err != nil {
			return err
		}
		(*e)[i] = res
	}
	return nil
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

func UnmarshalBaseStructAndFields[baseType any, fieldType1 any, fieldType2 any](
	b []byte, base *baseType,
	entry1 string, field1 *fieldType1,
	entry2 string, field2 *fieldType2) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if base != nil {
		if err := json.Unmarshal(b, base); err != nil {
			return err
		}
	}
	if err := unmarshalFromRaw(raw, entry1, field1); err != nil {
		return err
	}
	if field2 != nil {
		if err := unmarshalFromRaw(raw, entry2, field2); err != nil {
			return err
		}
	}
	return nil
}
