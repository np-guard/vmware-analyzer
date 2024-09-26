/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/common"
)

type treeNode interface {
	parent(resources *ResourcesContainerModel) treeNode
	name() string
}

////////////////////////////////////////////////////////////////////////////

func (v *VirtualNetworkInterface) parent(resources *ResourcesContainerModel) treeNode {
	if v.LportAttachmentId == nil {
		return nil
	}
	s := resources.GetSegmentPort(*v.LportAttachmentId)
	if s == nil {
		return nil
	}
	return s
}
func (s *SegmentPort) parent(resources *ResourcesContainerModel) treeNode {
	return resources.GetSegment(*s.ParentPath)
}
func (s *Segment) parent(resources *ResourcesContainerModel) treeNode {
	if s.ConnectivityPath == nil {
		return nil
	}
	if t1 := resources.GetTier1(*s.ConnectivityPath); t1 != nil {
		return t1
	}
	return resources.GetTier0(*s.ConnectivityPath)
}
func (t *Tier1) parent(resources *ResourcesContainerModel) treeNode {
	return resources.GetTier0(*t.Tier0Path)
}
func (t *Tier0) parent(resources *ResourcesContainerModel) treeNode { return nil }

////////////////////////////////////////////////////////////////////////////

func (v *VirtualNetworkInterface) name() string { return *v.DisplayName + "(ni)" }
func (s *SegmentPort) name() string             { return *s.DisplayName + "(sp)" }
func (s *Segment) name() string                 { return segmentName(s) + "(sg)" }
func (t *Tier1) name() string                   { return *t.DisplayName + "(t1)" }
func (t *Tier0) name() string                   { return *t.DisplayName + "(t0)" }

// //////////////////////////////////////////////////////////////////////
type treeNodeBranch []treeNode

func branch(resources *ResourcesContainerModel, n treeNode) treeNodeBranch {
	if n == nil {
		return treeNodeBranch{}
	}
	p := n.parent(resources)
	return append(branch(resources, p), n)
}
func treeNodesPath(got *ResourcesContainerModel, t1, t2 treeNode) (bool, treeNode, treeNodeBranch, treeNodeBranch) {
	b1 := branch(got, t1)
	b2 := branch(got, t2)
	if b1[0] != b2[0] {
		return false, nil, nil, nil
	}
	rootIndex := 0
	for i := range b1 {
		if b1[i] != b2[i] {
			break
		}
		rootIndex = i
	}
	return true, b1[rootIndex], b1[rootIndex+1:], b2[rootIndex+1:]
}

////////////////////////////////////////////////////////////////

func (resources *ResourcesContainerModel) GetSegment(query string) *Segment {
	i := slices.IndexFunc(resources.SegmentList, func(t Segment) bool { return query == *t.Path })
	return &resources.SegmentList[i]
}
func (resources *ResourcesContainerModel) GetSegmentPort(id string) *SegmentPort {
	for _, segment := range resources.SegmentList {
		i := slices.IndexFunc(segment.SegmentPorts, func(s SegmentPort) bool { return id == *s.Attachment.Id })
		if i >= 0 {
			return &segment.SegmentPorts[i]
		}
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////

func vniName(resources *ResourcesContainerModel, vni *VirtualNetworkInterface) string {
	addresses := []string{}
	for _, ai := range vni.IpAddressInfo {
		for _, a := range ai.IpAddresses {
			addresses = append(addresses, string(a))
		}
	}
	return fmt.Sprintf("%s\\n[%s]", *resources.GetVirtualMachine(*vni.OwnerVmId).DisplayName, strings.Join(addresses, ","))
}

func segmentName(segment *Segment) string {
	nAddresses := []string{}
	for _, subnet := range segment.Subnets {
		nAddresses = append(nAddresses, *subnet.Network)
	}
	return fmt.Sprintf("%s(%s)\\nnetworks[%s]", *segment.DisplayName, *segment.Type, strings.Join(nAddresses, ","))
}

/////////////////////////////////////////////////////////////////////////////////

func dotTopology(got *ResourcesContainerModel) {
	out := "digraph D {\n"
	for _, t1 := range got.Tier1List {
		t0 := got.GetTier0(*t1.Tier0Path)
		out += fmt.Sprintf("\"t1:%s\" -> \"t0:%s\"\n", *t1.DisplayName, *t0.DisplayName)
	}
	for _, segment := range got.SegmentList {
		if segment.ConnectivityPath == nil {
		} else if t1 := got.GetTier1(*segment.ConnectivityPath); t1 != nil {
			out += fmt.Sprintf("\"sg:%s\" -> \"t1:%s\"\n", segmentName(&segment), *t1.DisplayName)
		} else if t0 := got.GetTier0(*segment.ConnectivityPath); t0 != nil {
			out += fmt.Sprintf("\"sg:%s\" -> \"t0:%s\"\n", segmentName(&segment), *t0.DisplayName)
		}
		for _, port := range segment.SegmentPorts {
			att := *port.Attachment.Id
			vif := got.GetVirtualNetworkInterfaceByPort(att)
			out += fmt.Sprintf("\"ni:%s\" -> \"sg:%s\"\n", vniName(got, vif), segmentName(&segment))
			vm := got.GetVirtualMachine(*vif.OwnerVmId)
			out += fmt.Sprintf("\"vm:%s\" -> \"ni:%s\"\n", *vm.DisplayName, vniName(got, vif))
		}
	}
	out += "}\n"
	common.WriteToFile(path.Join("out/", "topology.dot"), out)
}

func connectionTopology(got *ResourcesContainerModel) {
	dotTopology(got)
	out := "digraph D {\n"

	for i1 := range got.VirtualNetworkInterfaceList {
		for i2 := range got.VirtualNetworkInterfaceList {
			v1 := &got.VirtualNetworkInterfaceList[i1]
			v2 := &got.VirtualNetworkInterfaceList[i2]
			c, r, b1, b2 := treeNodesPath(got, v1, v2)
			if i1 > i2 && c {
				out += fmt.Sprintf("\"%s\" -> \"%s\"[dir=none]\n", vniName(got, v1), vniName(got, v2))
				fmt.Printf("%s <-%d---%s---%d->%s\n", vniName(got, v1), len(b1), r.name(), len(b2), vniName(got, v2))
			}
		}
	}
	out += "}\n"
	common.WriteToFile(path.Join("out/", "connection.dot"), out)
}

////////////////////////////////////////////////////////////////////////////////////////////////
