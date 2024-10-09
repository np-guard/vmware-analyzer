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

const (
	TextFormat = "txt"
	DotFormat  = "dot"
)

func (resources *ResourcesContainerModel) OutputTopology(fileName, format string) (res string, err error) {
	switch format {
	case TextFormat:
		res,err = resources.createTopologyTree().ToJSONString()
	case DotFormat:
		res = resources.createTopologyDotGraph().String()
	}
	if err != nil {
		return "", err
	}
if fileName != "" {
		err := common.WriteToFile(fileName, res)
		if err != nil {
			return "", err
		}
	}
	return res, nil
}

func (resources *ResourcesContainerModel) createTopologyDotGraph() *common.DotGraph {
	g := common.NewDotGraph()
	for t1i := range resources.Tier1List {
		t0 := resources.GetTier0(*resources.Tier1List[t1i].Tier0Path)
		g.AddEdge(&resources.Tier1List[t1i], t0, "")
	}
	for si := range resources.SegmentList {
		segment := &resources.SegmentList[si]
		if segment.ConnectivityPath == nil {
		} else if t1 := resources.GetTier1(*segment.ConnectivityPath); t1 != nil {
			g.AddEdge(segment, t1, "")
		} else if t0 := resources.GetTier0(*segment.ConnectivityPath); t0 != nil {
			g.AddEdge(segment, t0, "")
		}
		for pi := range segment.SegmentPorts {
			att := *segment.SegmentPorts[pi].Attachment.Id
			vni := resources.GetVirtualNetworkInterfaceByPort(att)
			g.AddEdge(vni, segment, "")
			vm := resources.GetVirtualMachine(*vni.OwnerVmId)
			g.AddEdge(vm, vni, "")
		}
	}
	return g
}

func (resources *ResourcesContainerModel) createTopologyTree() *TreeNode2 {
	root := newTreeNode("root")
	allTreeNodes := map[interface{}]*TreeNode2{}
	for t0i := range resources.Tier0List {
		t0 := &resources.Tier0List[t0i]
		allTreeNodes[t0] = newTreeNode(t0.Name())
		root.addChild("t0s", allTreeNodes[t0])
	}
	for t1i := range resources.Tier1List {
		t1 := &resources.Tier1List[t1i]
		allTreeNodes[t1] = newTreeNode(t1.Name())
		t0 := resources.GetTier0(*resources.Tier1List[t1i].Tier0Path)
		allTreeNodes[t0].addChild("t1s", allTreeNodes[t1])
	}
	for si := range resources.SegmentList {
		segment := &resources.SegmentList[si]
		allTreeNodes[segment] = newTreeNode(segment.Name())
		if segment.ConnectivityPath == nil {
		} else if t1 := resources.GetTier1(*segment.ConnectivityPath); t1 != nil {
			allTreeNodes[t1].addChild("segments", allTreeNodes[segment])
		} else if t0 := resources.GetTier0(*segment.ConnectivityPath); t0 != nil {
			allTreeNodes[t0].addChild("segments", allTreeNodes[segment])
		}
		for pi := range segment.SegmentPorts {
			att := *segment.SegmentPorts[pi].Attachment.Id
			vni := resources.GetVirtualNetworkInterfaceByPort(att)
			allTreeNodes[vni] = newTreeNode(vni.Name())
			allTreeNodes[segment].addChild("vnis", allTreeNodes[vni])
			vm := resources.GetVirtualMachine(*vni.OwnerVmId)
			allTreeNodes[vm] = newTreeNode(vm.Name())
			allTreeNodes[vni].addChild("vms", allTreeNodes[vm])
		}
	}
	return root
}

type treeNodeChildren map[string][]*TreeNode2
type TreeNode2 struct {
	Children treeNodeChildren
	Name string
}

func newTreeNode(name string)*TreeNode2{
	return &TreeNode2{treeNodeChildren{}, name}
}

func (tn *TreeNode2) addChild(cType string, c *TreeNode2) {
	if _, ok := tn.Children[cType]; !ok {
		tn.Children[cType] = []*TreeNode2{}
	}
	tn.Children[cType] = append(tn.Children[cType], c)
}

func (tn *TreeNode2) ToJSONString() (string, error) {
	toPrint, err := json.MarshalIndent(tn, "", "    ")
	return string(toPrint), err
}
