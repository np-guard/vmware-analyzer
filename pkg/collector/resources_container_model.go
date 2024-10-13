/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/common"
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
	for si := range resources.SegmentList {
		i := slices.IndexFunc(resources.SegmentList[si].SegmentPorts, func(s SegmentPort) bool { return id == *s.Attachment.Id })
		if i >= 0 {
			return &resources.SegmentList[si].SegmentPorts[i]
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////

func (t0 *Tier0) Name() string                    { return *t0.DisplayName }
func (t1 *Tier1) Name() string                    { return *t1.DisplayName }
func (s *Segment) Name() string                   { return *s.DisplayName }
func (vni *VirtualNetworkInterface) Name() string { return *vni.DisplayName }
func (vm *VirtualMachine) Name() string           { return *vm.DisplayName }

func (t0 *Tier0) Kind() string                    { return "t0" }
func (t1 *Tier1) Kind() string                    { return "t1" }
func (s *Segment) Kind() string                   { return "segment" }
func (vni *VirtualNetworkInterface) Kind() string { return "vni" }
func (vm *VirtualMachine) Kind() string           { return "vm" }

func (resources *ResourcesContainerModel) OutputTopologyGraph(fileName, format string) (res string, err error) {
	var g common.Graph
	switch format {
	case common.JsonFormat:
		g = common.NewTreeGraph()
	case common.TextFormat:
		g = common.NewEdgesGraph()
	case common.DotFormat:
		g = common.NewDotGraph(true)
	}
	resources.CreateTopologyGraph(g)
	return common.OutputGraph(g, fileName, format)
}

func (resources *ResourcesContainerModel) CreateTopologyGraph(g common.Graph) {
	for t0i := range resources.Tier0List {
		g.AddEdge(nil, &resources.Tier0List[t0i], nil)
	}
	for t1i := range resources.Tier1List {
		t0 := resources.GetTier0(*resources.Tier1List[t1i].Tier0Path)
		g.AddEdge(t0, &resources.Tier1List[t1i], nil)
	}
	for si := range resources.SegmentList {
		segment := &resources.SegmentList[si]
		if segment.ConnectivityPath == nil {
			g.AddEdge(nil, segment, nil)
		} else if t1 := resources.GetTier1(*segment.ConnectivityPath); t1 != nil {
			g.AddEdge(t1, segment, nil)
		} else if t0 := resources.GetTier0(*segment.ConnectivityPath); t0 != nil {
			g.AddEdge(t0, segment, nil)
		}
		for pi := range segment.SegmentPorts {
			att := *segment.SegmentPorts[pi].Attachment.Id
			vni := resources.GetVirtualNetworkInterfaceByPort(att)
			g.AddEdge(segment, vni, nil)
			vm := resources.GetVirtualMachine(*vni.OwnerVmId)
			g.AddEdge(vni, vm, nil)
		}
	}
}
