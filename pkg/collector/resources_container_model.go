/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"slices"

	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

// ResourcesContainerModel defines the model of a container for all resource types we can collect
type ResourcesContainerModel struct {
	ServiceList                 []Service                 `json:"services"`
	VirtualMachineList          []VirtualMachine          `json:"virtual_machines"`
	VirtualNetworkInterfaceList []VirtualNetworkInterface `json:"virtual_network_interface"`
	SegmentList                 []Segment                 `json:"segments"`
	Tier0List                   []Tier0                   `json:"tier0"`
	Tier1List                   []Tier1                   `json:"tier1"`
	DomainList                  []Domain                  `json:"domains"`
}
type DomainResources struct {
	SecurityPolicyList []SecurityPolicy `json:"security_policies"`
	GroupList          []Group          `json:"groups"`
}

// NewResourcesContainerModel creates an empty resources container
func NewResourcesContainerModel() *ResourcesContainerModel {
	nsx.FixResourcesCode()
	return &ResourcesContainerModel{}
}

// ToJSONString converts a ResourcesContainerModel into a json-formatted-string
func (resources *ResourcesContainerModel) ToJSONString() (string, error) {
	toPrint, err := json.MarshalIndent(resources, "", "    ")
	return string(toPrint), err
}

func FromJSONString(b []byte) (*ResourcesContainerModel, error) {
	resources := NewResourcesContainerModel()
	err := json.Unmarshal(b, resources)
	return resources, err
}

func (resources *DomainResources) GetGroup(query string) *Group {
	i := slices.IndexFunc(resources.GroupList, func(gr Group) bool { return query == *gr.Path })
	return &resources.GroupList[i]
}

func (resources *ResourcesContainerModel) GetService(query string) *Service {
	i := slices.IndexFunc(resources.ServiceList, func(gr Service) bool { return query == *gr.Path })
	return &resources.ServiceList[i]
}

func (resources *ResourcesContainerModel) GetVirtualNetworkInterfaceByPort(portID string) *VirtualNetworkInterface {
	i := slices.IndexFunc(resources.VirtualNetworkInterfaceList, func(vni VirtualNetworkInterface) bool {
		return vni.LportAttachmentId != nil && portID == *vni.LportAttachmentId
	})
	return &resources.VirtualNetworkInterfaceList[i]
}

func (resources *ResourcesContainerModel) GetVirtualMachine(id string) *VirtualMachine {
	i := slices.IndexFunc(resources.VirtualMachineList, func(vm VirtualMachine) bool { return id == *vm.ExternalId })
	return &resources.VirtualMachineList[i]
}

func (resources *ResourcesContainerModel) GetTier0(query string) *Tier0 {
	i := slices.IndexFunc(resources.Tier0List, func(t Tier0) bool { return query == *t.Path })
	if i >= 0 {
		return &resources.Tier0List[i]
	}
	return nil
}
func (resources *ResourcesContainerModel) GetTier1(query string) *Tier1 {
	i := slices.IndexFunc(resources.Tier1List, func(t Tier1) bool { return query == *t.Path })
	if i >= 0 {
		return &resources.Tier1List[i]
	}
	return nil
}

func (resources *ResourcesContainerModel) GetSegment(query string) *Segment {
	i := slices.IndexFunc(resources.SegmentList, func(t Segment) bool { return query == *t.Path })
	return &resources.SegmentList[i]
}

func (resources *ResourcesContainerModel) GetSegmentPort(id string) *SegmentPort {
	for i := range resources.SegmentList {
		i := slices.IndexFunc(resources.SegmentList[i].SegmentPorts, func(s SegmentPort) bool { return id == *s.Attachment.Id })
		if i >= 0 {
			return &resources.SegmentList[i].SegmentPorts[i]
		}
	}
	return nil
}
