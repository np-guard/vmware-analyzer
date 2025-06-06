/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"slices"

	"github.com/np-guard/vmware-analyzer/internal/common"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
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
	SecurityPolicyList    []SecurityPolicy    `json:"security_policies"`
	GatewayPolicyList     []GatewayPolicy     `json:"gateway_policies"`
	RedirectionPolicyList []RedirectionPolicy `json:"redirection_policies"`
	GroupList             []Group             `json:"groups"`
}

// NewResourcesContainerModel creates an empty resources container
func NewResourcesContainerModel() *ResourcesContainerModel {
	nsx.FixResourcesCode()
	return &ResourcesContainerModel{}
}

// ToJSONString converts a ResourcesContainerModel into a json-formatted-string
func (resources *ResourcesContainerModel) ToJSONString() (string, error) {
	return common.MarshalJSON(resources)
}

func FromJSONString(b []byte) (*ResourcesContainerModel, error) {
	resources := NewResourcesContainerModel()
	err := json.Unmarshal(b, resources)
	return resources, err
}

func (resources *ResourcesContainerModel) FindGroupByPath(path string) *Group {
	for i := range resources.DomainList {
		if g := resources.DomainList[i].Resources.GetGroup(path); g != nil {
			return g
		}
	}
	return nil
}

func (resources *DomainResources) GetGroup(query string) *Group {
	i := slices.IndexFunc(resources.GroupList, func(gr Group) bool { return query == common.SafePointerDeref(gr.Path) })
	if i < 0 {
		return nil
	}
	return &resources.GroupList[i]
}

func (resources *ResourcesContainerModel) GetService(query string) *Service {
	i := slices.IndexFunc(resources.ServiceList, func(gr Service) bool { return query == common.SafePointerDeref(gr.Path) })
	if i < 0 {
		return nil
	}
	return &resources.ServiceList[i]
}

func (resources *ResourcesContainerModel) GetVirtualNetworkInterfaceByPort(portID string) *VirtualNetworkInterface {
	i := slices.IndexFunc(resources.VirtualNetworkInterfaceList, func(vni VirtualNetworkInterface) bool {
		return vni.LportAttachmentId != nil && portID == *vni.LportAttachmentId
	})
	return &resources.VirtualNetworkInterfaceList[i]
}

func (resources *ResourcesContainerModel) GetVirtualMachineAddresses(vmID string) []string {
	ips := []string{}
	for i := range resources.VirtualNetworkInterfaceList {
		vni := &resources.VirtualNetworkInterfaceList[i]
		if *vni.OwnerVmId == vmID {
			for _, info := range vni.IpAddressInfo {
				for _, address := range info.IpAddresses {
					ips = append(ips, string(address))
				}
			}
		}
	}
	return ips
}

func (resources *ResourcesContainerModel) GetVirtualNetworkInterfaceByAddress(address string) *VirtualNetworkInterface {
	i := slices.IndexFunc(resources.VirtualNetworkInterfaceList, func(vni VirtualNetworkInterface) bool {
		return len(vni.IpAddressInfo) > 0 &&
			len(vni.IpAddressInfo[0].IpAddresses) > 0 &&
			vni.IpAddressInfo[0].IpAddresses[0] == nsx.IPAddress(address)
	})
	if i >= 0 {
		return &resources.VirtualNetworkInterfaceList[i]
	}
	return nil
}

func (resources *ResourcesContainerModel) GetVirtualMachine(id string) *VirtualMachine {
	i := slices.IndexFunc(resources.VirtualMachineList, func(vm VirtualMachine) bool { return id == *vm.ExternalId })
	return &resources.VirtualMachineList[i]
}

func (resources *ResourcesContainerModel) GetVMsByNames(names []string) (res []VirtualMachine) {
	for i := range resources.VirtualMachineList {
		if slices.Contains(names, common.SafePointerDeref(resources.VirtualMachineList[i].DisplayName)) {
			res = append(res, resources.VirtualMachineList[i])
		}
	}
	return res
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

func (resources *ResourcesContainerModel) GetSegmentsOfTier1(t1 *Tier1) (res []*Segment) {
	// find all segments with ConnectivityPath equal to t1.Path
	if t1.Path == nil {
		return res
	}
	t1Path := *t1.Path
	for i := range resources.SegmentList {
		seg := &resources.SegmentList[i]
		if seg.ConnectivityPath != nil && *seg.ConnectivityPath == t1Path {
			res = append(res, seg)
		}
	}
	return res
}

func (resources *ResourcesContainerModel) GetSegmentsOfTier0(t0 *Tier0) (res []*Segment) {
	// find all segments with ConnectivityPath equal to t0.Path
	if t0.Path == nil {
		return res
	}
	t0Path := *t0.Path
	for i := range resources.SegmentList {
		seg := &resources.SegmentList[i]
		if seg.ConnectivityPath != nil && *seg.ConnectivityPath == t0Path {
			res = append(res, seg)
		}
	}
	return res
}

func (resources *ResourcesContainerModel) GetT1sOfTier0(t0 *Tier0) (res []*Tier1) {
	if t0.Path == nil {
		return res
	}
	t0Path := *t0.Path
	// find all t1 gws with Tier0Path equal to t0.Path
	for i := range resources.Tier1List {
		t1 := &resources.Tier1List[i]
		if t1.Tier0Path != nil && *t1.Tier0Path == t0Path {
			res = append(res, t1)
		}
	}
	return res
}

func (resources *ResourcesContainerModel) GetSegment(query string) *Segment {
	i := slices.IndexFunc(resources.SegmentList, func(t Segment) bool { return query == *t.Path })
	if i < 0 {
		return nil
	}
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

func (resources *ResourcesContainerModel) GetRule(id string) *FirewallRule {
	for d := range resources.DomainList {
		for s := range resources.DomainList[d].Resources.SecurityPolicyList {
			if resources.DomainList[d].Resources.SecurityPolicyList[s].DefaultRule != nil {
				if *resources.DomainList[d].Resources.SecurityPolicyList[s].DefaultRule.Id == id {
					return resources.DomainList[d].Resources.SecurityPolicyList[s].DefaultRule
				}
			}
			for r := range resources.DomainList[d].Resources.SecurityPolicyList[s].Rules {
				if *resources.DomainList[d].Resources.SecurityPolicyList[s].Rules[r].FirewallRule.Id == id {
					return resources.DomainList[d].Resources.SecurityPolicyList[s].Rules[r].FirewallRule
				}
			}
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////

func (t0 *Tier0) Name() string                    { return common.SafePointerDeref(t0.DisplayName) }
func (t1 *Tier1) Name() string                    { return common.SafePointerDeref(t1.DisplayName) }
func (segment *Segment) Name() string             { return common.SafePointerDeref(segment.DisplayName) }
func (vni *VirtualNetworkInterface) Name() string { return common.SafePointerDeref(vni.DisplayName) }
func (vm *VirtualMachine) Name() string           { return common.SafePointerDeref(vm.DisplayName) }

func (t0 *Tier0) Kind() string                    { return "t0" }
func (t1 *Tier1) Kind() string                    { return "t1" }
func (segment *Segment) Kind() string             { return "segment" }
func (vni *VirtualNetworkInterface) Kind() string { return "vni" }
func (vm *VirtualMachine) Kind() string           { return "VM" }

func (resources *ResourcesContainerModel) GetVMsOfSegment(segment *Segment) (res []*VirtualMachine) {
	for pi := range segment.SegmentPorts {
		att := *segment.SegmentPorts[pi].Attachment.Id
		vni := resources.GetVirtualNetworkInterfaceByPort(att)
		vm := resources.GetVirtualMachine(*vni.OwnerVmId)
		res = append(res, vm)
	}
	return res
}
