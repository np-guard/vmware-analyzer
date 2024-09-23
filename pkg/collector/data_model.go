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
	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	rulesJsonEntry          = "rules"
	membersJsonEntry        = "members"
	expressionJsonEntry     = "expression"
	resourcesJsonEntry      = "resources"
	serviceEntriesJsonEntry = "service_entries"
	resourceTypeJsonEntry   = "resource_type"
)

type Rule struct {
	resources.Rule
	ServiceEntries ServiceEntries `json:"service_entries"`
}

func (r *Rule) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var res Rule
	if err := json.Unmarshal(b, &res.Rule); err != nil {
		return err
	}
	if r, ok := raw[serviceEntriesJsonEntry]; ok {
		if err := json.Unmarshal(r, &res.ServiceEntries); err != nil {
			return err
		}
	} else {
		res.ServiceEntries = ServiceEntries{}
	}
	*r = res
	return nil
}

type SecurityPolicy struct {
	resources.SecurityPolicy
	Rules []Rule `json:"rules"`
}

func (s *SecurityPolicy) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var res SecurityPolicy
	if err := json.Unmarshal(b, &res.SecurityPolicy); err != nil {
		return err
	}
	if r, ok := raw[rulesJsonEntry]; ok {
		if err := json.Unmarshal(r, &res.Rules); err != nil {
			return err
		}
	}
	*s = res
	return nil
}

// /////////////////////////////////////////////////////////////////////////////////////
type IPProtocolServiceEntry struct {
	resources.IPProtocolServiceEntry
}

func (e *IPProtocolServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf("fail to create a connection from service %v", e.ResourceType)
}

type IGMPTypeServiceEntry struct {
	resources.IGMPTypeServiceEntry
}

func (e *IGMPTypeServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf("fail to create a connection from service %v", e.ResourceType)
}

type ICMPTypeServiceEntry struct {
	resources.ICMPTypeServiceEntry
}

func (e *ICMPTypeServiceEntry) ToConnection() (*connection.Set, error) {
	if e.IcmpCode == nil || e.IcmpType == nil {
		return nil, fmt.Errorf("fail to create a connection from service %v", e.ResourceType)
	}
	c := int64(*e.IcmpCode)
	t := int64(*e.IcmpType)
	return connection.ICMPConnection(t, t, c, c), nil
}

type ALGTypeServiceEntry struct {
	resources.ALGTypeServiceEntry
}

func (e *ALGTypeServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf("fail to create a connection from service %v", e.ResourceType)
}

type L4PortSetServiceEntry struct {
	resources.L4PortSetServiceEntry
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

func parsePorts(ports []resources.PortElement) ([]struct{ min, max int64 }, error) {
	res := make([]struct{ min, max int64 }, len(ports))
	if len(ports) == 0 {
		return []struct{ min, max int64 }{{connection.MinPort, connection.MaxPort}}, nil
	}
	for i, portString := range ports {
		var err error
		if strings.Contains(string(portString), "-") {
			_, err = fmt.Sscanf(string(portString), "%s-%s", res[i].min, res[i].max)
		} else {
			_, err = fmt.Sscanf(string(portString), "%s", res[i].min)
			res[i].max = res[i].min
		}
		if err != nil {
			return nil, err
		}

	}
	return res, nil
}

type EtherTypeServiceEntry struct {
	resources.EtherTypeServiceEntry
}

func (e *EtherTypeServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf("fail to create a connection from service %v", e.ResourceType)
}

type NestedServiceServiceEntry struct {
	resources.NestedServiceServiceEntry
}

func (e *NestedServiceServiceEntry) ToConnection() (*connection.Set, error) {
	return nil, fmt.Errorf("fail to create a connection from service %v", e.ResourceType)
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
		if err := json.Unmarshal(raw[resourceTypeJsonEntry], &cType); err != nil {
			return err
		}
		switch cType {
		case "IPProtocolServiceEntry":
			res := &IPProtocolServiceEntry{}
			if err := json.Unmarshal(rawMessage, res); err != nil {
				return err
			}
			(*s)[i] = res
		case "IGMPTypeServiceEntry":
			res := &IGMPTypeServiceEntry{}
			if err := json.Unmarshal(rawMessage, res); err != nil {
				return err
			}
			(*s)[i] = res
		case "ICMPTypeServiceEntry":
			res := &ICMPTypeServiceEntry{}
			if err := json.Unmarshal(rawMessage, res); err != nil {
				return err
			}
			(*s)[i] = res
		case "ALGTypeServiceEntry":
			res := &ALGTypeServiceEntry{}
			if err := json.Unmarshal(rawMessage, res); err != nil {
				return err
			}
			(*s)[i] = res
		case "L4PortSetServiceEntry":
			var res = &L4PortSetServiceEntry{}
			if err := json.Unmarshal(rawMessage, res); err != nil {
				return err
			}
			(*s)[i] = res
		case "EtherTypeServiceEntry":
			res := &EtherTypeServiceEntry{}
			if err := json.Unmarshal(rawMessage, res); err != nil {
				return err
			}
			(*s)[i] = res
		case "NestedServiceServiceEntry":
			res := &NestedServiceServiceEntry{}
			if err := json.Unmarshal(rawMessage, res); err != nil {
				return err
			}
			(*s)[i] = res
		default:
			return fmt.Errorf("fail to unmarshal entry %s", rawMessage)
		}
	}
	return nil
}

type Service struct {
	resources.Service
	ServiceEntries ServiceEntries `json:"service_entries"`
}

func (s *Service) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var res Service
	if err := json.Unmarshal(b, &res.Service); err != nil {
		return err
	}
	if m, ok := raw[serviceEntriesJsonEntry]; ok {
		if err := json.Unmarshal(m, &res.ServiceEntries); err != nil {
			return err
		}
	}
	*s = res
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////

type VirtualMachine struct {
	resources.VirtualMachine
}
type Segment struct {
	resources.Segment
}
type RealizedVirtualMachine struct {
	resources.RealizedVirtualMachine
}

///////////////////////////////////////////////////////////////////////////////////////

type ExpressionElement interface {
	expressionElementIsMe()
}

type Condition struct {
	resources.Condition
}

func (Condition) expressionElementIsMe() {}

type ConjunctionOperator struct {
	resources.ConjunctionOperator
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
		if err := json.Unmarshal(raw[resourceTypeJsonEntry], &cType); err != nil {
			return err
		}
		switch cType {
		case "Condition":
			var res Condition
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*e)[i] = res
		case "ConjunctionOperator":
			var res ConjunctionOperator
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*e)[i] = res
		default:
			return fmt.Errorf("fail to unmarshal expression %s", rawMessage)
		}
	}
	return nil
}

type Group struct {
	resources.Group
	Members    []RealizedVirtualMachine `json:"members"`
	Expression Expression               `json:"expression"`
}

func (d *Group) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var res Group
	if err := json.Unmarshal(b, &res.Group); err != nil {
		return err
	}
	if m, ok := raw[membersJsonEntry]; ok {
		if err := json.Unmarshal(m, &res.Members); err != nil {
			return err
		}
	}
	if m, ok := raw[expressionJsonEntry]; ok {
		if err := json.Unmarshal(m, &res.Expression); err != nil {
			return err
		}
	}
	*d = res
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////

type Domain struct {
	resources.Domain
	Resources DomainResources `json:"resources"`
}

func (d *Domain) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var res Domain
	if err := json.Unmarshal(b, &res.Domain); err != nil {
		return err
	}
	if m, ok := raw[resourcesJsonEntry]; ok {
		if err := json.Unmarshal(m, &res.Resources); err != nil {
			return err
		}
	}
	*d = res
	return nil
}
