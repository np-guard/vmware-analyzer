/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector/version"
	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

// ResourcesContainerModel defines the model of a container for all resource types we can collect
type ResourcesContainerModel struct {
	ResourceModelMetadata
	SecurityPolicyList []*SecurityPolicy `json:"security_policies"`
	VirtualMachineList []*VirtualMachine `json:"virtual_machines"`
}

// NewResourcesContainerModel creates an empty resources container
func NewResourcesContainerModel() *ResourcesContainerModel {
	return &ResourcesContainerModel{
		SecurityPolicyList:    []*SecurityPolicy{},
		VirtualMachineList:    []*VirtualMachine{},
		ResourceModelMetadata: ResourceModelMetadata{Version: version.VersionCore},
	}
}

// PrintStats outputs the number of items of each type
func (resources *ResourcesContainerModel) PrintStats() {
	fmt.Printf("Found %d security groups\n", len(resources.SecurityPolicyList))
	fmt.Printf("Found %d virtual machines\n", len(resources.VirtualMachineList))
}

// ToJSONString converts a ResourcesContainerModel into a json-formatted-string
func (resources *ResourcesContainerModel) ToJSONString() (string, error) {
	toPrint, err := json.MarshalIndent(resources, "", "    ")
	return string(toPrint), err
}

type SecurityPolicy struct {
	resources.SecurityPolicy
}

func NewSecurityPolicy(securityPolicy *resources.SecurityPolicy) *SecurityPolicy {
	return &SecurityPolicy{SecurityPolicy: *securityPolicy}
}

func (res *SecurityPolicy) UnmarshalJSON(data []byte) error {
	return res.UnmarshalJSON(data)
	// return basicUnmarshal[resources.SecurityPolicy](data, resources.UnmarshalJSON, &res.SecurityPolicy, &res.BaseTaggedResource)
}

type VirtualMachine struct {
	resources.VirtualMachine
}

func NewVirtualMachine(virtualMachine *resources.VirtualMachine) *VirtualMachine {
	return &VirtualMachine{VirtualMachine: *virtualMachine}
}
