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
type RealizedVirtualMachine struct{
	resources.RealizedVirtualMachine
}

type Group struct {
	resources.Group
	Members []RealizedVirtualMachine
}
type Service struct {
	resources.Service
}
type Segment struct {
	resources.Segment
}
type Domain struct {
	resources.Domain
	DomainResources
}
