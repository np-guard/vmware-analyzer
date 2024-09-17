/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

type SecurityPolicy struct {
	resources.SecurityPolicy
}

type VirtualMachine struct {
	resources.VirtualMachine
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
	Members    []RealizedVirtualMachine
	Expression []Exprssion
}
type Service struct {
	resources.Service
}
type Segment struct {
	resources.Segment
}
type Domain struct {
	resources.Domain
	Resources DomainResources
}
