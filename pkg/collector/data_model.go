/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
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
	if r, ok := raw["service_entries"]; ok {
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
	if r, ok := raw["rules"]; ok {
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

func (e IPProtocolServiceEntry) ToConnection() *connection.Set {
	return nil
}

type IGMPTypeServiceEntry struct {
	resources.IGMPTypeServiceEntry
}

func (e IGMPTypeServiceEntry) ToConnection() *connection.Set {
	return nil
}

type ICMPTypeServiceEntry struct {
	resources.ICMPTypeServiceEntry
}

func (e ICMPTypeServiceEntry) ToConnection() *connection.Set {
	if e.IcmpCode == nil || e.IcmpType == nil {
		return nil
	}
	c := int64(*e.IcmpCode)
	t := int64(*e.IcmpType)
	return connection.ICMPConnection(t, t, c, c)
}

type ALGTypeServiceEntry struct {
	resources.ALGTypeServiceEntry
}

func (e ALGTypeServiceEntry) ToConnection() *connection.Set {
	return nil
}

type L4PortSetServiceEntry struct {
	resources.L4PortSetServiceEntry
}

func (e L4PortSetServiceEntry) ToConnection() *connection.Set {
	res := connection.None()
	protocol := netp.ProtocolString(*e.L4Protocol)
	srcPorts := parsePorts(e.SourcePorts)
	dstPorts := parsePorts(e.DestinationPorts)
	for _, sp := range srcPorts {
		for _, dp := range dstPorts {
			res.Union(connection.TCPorUDPConnection(protocol, sp.min, sp.max, dp.min, dp.max))
		}
	}
	return res
}

func parsePorts(ports []resources.PortElement) []struct{ min, max int64 } {
	res := make([]struct{ min, max int64 }, len(ports))
	if len(ports) == 0 {
		return []struct{ min, max int64 }{{connection.MinPort, connection.MaxPort}}
	}
	for i, portString := range ports {
		if strings.Contains(string(portString), "-") {
			fmt.Sscanf(string(portString), "%s-%s", res[i].min, res[i].max)
		} else {
			res[i].min, _ = strconv.ParseInt(string(portString), 10, 64)
			res[i].max = res[i].min
		}
	}
	return res
}

type EtherTypeServiceEntry struct {
	resources.EtherTypeServiceEntry
}

func (e EtherTypeServiceEntry) ToConnection() *connection.Set {
	return nil
}

type NestedServiceServiceEntry struct {
	resources.NestedServiceServiceEntry
}

func (e NestedServiceServiceEntry) ToConnection() *connection.Set {
	return nil
}

type ServiceEntry interface {
	ToConnection() *connection.Set
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
		cType := string(raw["resource_type"])

		switch cType {
		case "\"IPProtocolServiceEntry\"":
			var res IPProtocolServiceEntry
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*s)[i] = res
		case "\"IGMPTypeServiceEntry\"":
			var res IGMPTypeServiceEntry
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*s)[i] = res
		case "\"ICMPTypeServiceEntry\"":
			var res ICMPTypeServiceEntry
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*s)[i] = res
		case "\"ALGTypeServiceEntry\"":
			var res ALGTypeServiceEntry
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*s)[i] = res
		case "\"L4PortSetServiceEntry\"":
			var res L4PortSetServiceEntry
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*s)[i] = res
		case "\"EtherTypeServiceEntry\"":
			var res EtherTypeServiceEntry
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*s)[i] = res
		case "\"NestedServiceServiceEntry\"":
			var res NestedServiceServiceEntry
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*s)[i] = res
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
	if m, ok := raw["service_entries"]; ok {
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
		cType := string(raw["resource_type"])
		switch cType {
		case "\"Condition\"":
			var res Condition
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*e)[i] = res
		case "\"ConjunctionOperator\"":
			var res ConjunctionOperator
			if err := json.Unmarshal(rawMessage, &res); err != nil {
				return err
			}
			(*e)[i] = res
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
	if m, ok := raw["members"]; ok {
		if err := json.Unmarshal(m, &res.Members); err != nil {
			return err
		}
	}
	if m, ok := raw["expression"]; ok {
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
	if m, ok := raw["resources"]; ok {
		if err := json.Unmarshal(m, &res.Resources); err != nil {
			return err
		}
	}
	*d = res
	return nil
}
