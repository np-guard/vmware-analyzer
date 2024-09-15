/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"slices"
)

// ResourcesContainerModel defines the model of a container for all resource types we can collect
type ResourcesContainerModel struct {
	ServiceList        []Service        `json:"services"`
	VirtualMachineList []VirtualMachine `json:"virtual_machines"`
	SegmentList        []Segment        `json:"segments"`
	DomainList         []Domain         `json:"domains"`
}
type DomainResources struct {
	SecurityPolicyList []SecurityPolicy `json:"security_policies"`
	GroupList          []Group          `json:"groups"`
}

// NewResourcesContainerModel creates an empty resources container
func NewResourcesContainerModel() *ResourcesContainerModel {
	return &ResourcesContainerModel{}
}

// ToJSONString converts a ResourcesContainerModel into a json-formatted-string
func (resources *ResourcesContainerModel) ToJSONString() (string, error) {
	toPrint, err := json.MarshalIndent(resources, "", "    ")
	return string(toPrint), err
}

func (resources *DomainResources) getGroup(query string) *Group {
	i := slices.IndexFunc(resources.GroupList, func(gr Group) bool { return query == *gr.Path })
	return &resources.GroupList[i]
}
