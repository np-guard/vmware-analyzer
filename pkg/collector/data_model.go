/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"

	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

type SecurityPolicy struct {
	resources.SecurityPolicy
}

type Service struct {
	resources.Service
}
type VirtualMachine struct {
	resources.VirtualMachine
}
type Segment struct {
	resources.Segment
}
type RealizedVirtualMachine struct {
	resources.RealizedVirtualMachine
}

type Condition struct {
	resources.Condition
}

type ConjunctionOperator struct {
	resources.ConjunctionOperator
}
type Exprssion interface {
}

type Group struct {
	resources.Group
	Members    []RealizedVirtualMachine `json:"members"`
	Expression []Exprssion              `json:"expression"`
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
