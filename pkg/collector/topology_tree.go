/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import "github.com/np-guard/vmware-analyzer/internal/common"

// OutputTopologyGraph is the main function to get analyzed topology output
func (resources *ResourcesContainerModel) OutputTopologyGraph(fileName string, format common.OutFormat) (res string, err error) {
	var g common.Graph
	switch format {
	case common.JSONFormat:
		g = common.NewTreeGraph()
	case common.TextFormat:
		g = common.NewEdgesGraph("topology", []string{}, false)
	case common.DotFormat, common.SVGFormat:
		g = common.NewDotGraph(true)
	}
	resources.createTopologyGraph(g)
	return common.OutputGraph(g, fileName, format)
}

func (resources *ResourcesContainerModel) createTopologyGraph(g common.Graph) {
	for t0i := range resources.Tier0List {
		g.AddEdge(nil, &resources.Tier0List[t0i], nil)
	}
	for t1i := range resources.Tier1List {
		t0 := resources.GetTier0(common.SafePointerDeref(resources.Tier1List[t1i].Tier0Path))
		if t0 != nil {
			g.AddEdge(t0, &resources.Tier1List[t1i], nil)
		}
	}
	for si := range resources.SegmentList {
		segment := &resources.SegmentList[si]
		if segment.ConnectivityPath == nil {
			g.AddEdge(nil, segment, nil)
		} else if t1 := resources.GetTier1(common.SafePointerDeref(segment.ConnectivityPath)); t1 != nil {
			g.AddEdge(t1, segment, nil)
		} else if t0 := resources.GetTier0(common.SafePointerDeref(segment.ConnectivityPath)); t0 != nil {
			g.AddEdge(t0, segment, nil)
		}
		for pi := range segment.SegmentPorts {
			att := *segment.SegmentPorts[pi].Attachment.Id
			vni := resources.GetVirtualNetworkInterfaceByPort(att)
			//nolint: gocritic // keep commented-out code for now
			// g.AddEdge(segment, vni, nil)
			// g.AddEdge(vni, vm, nil)
			vm := resources.GetVirtualMachine(common.SafePointerDeref(vni.OwnerVmId))
			g.AddEdge(segment, vm, common.LabelFromString(vni.Name()))
		}
	}
}

type treeNode interface {
	parent(resources *ResourcesContainerModel) treeNode
}

////////////////////////////////////////////////////////////////////////////

func (vni *VirtualNetworkInterface) parent(resources *ResourcesContainerModel) treeNode {
	if vni.LportAttachmentId == nil {
		return nil
	}
	s := resources.GetSegmentPort(*vni.LportAttachmentId)
	if s == nil {
		return nil
	}
	return s
}
func (sp *SegmentPort) parent(resources *ResourcesContainerModel) treeNode {
	return resources.GetSegment(*sp.ParentPath)
}
func (segment *Segment) parent(resources *ResourcesContainerModel) treeNode {
	if segment.ConnectivityPath == nil {
		return nil
	}
	if t1 := resources.GetTier1(*segment.ConnectivityPath); t1 != nil {
		return t1
	}
	return resources.GetTier0(*segment.ConnectivityPath)
}
func (t1 *Tier1) parent(resources *ResourcesContainerModel) treeNode {
	return resources.GetTier0(*t1.Tier0Path)
}
func (t0 *Tier0) parent(resources *ResourcesContainerModel) treeNode { return nil }

// //////////////////////////////////////////////////////////////////////
type treeNodeBranch []treeNode

func branch(resources *ResourcesContainerModel, n treeNode) treeNodeBranch {
	if n == nil {
		return treeNodeBranch{}
	}
	p := n.parent(resources)
	return append(branch(resources, p), n)
}

// func treeNodesPath(got *ResourcesContainerModel, t1, t2 treeNode) (isConnected bool, root treeNode, b1, b2 treeNodeBranch) {
// 	b1 = branch(got, t1)
// 	b2 = branch(got, t2)
// 	isConnected = b1[0] == b2[0]
// 	if !isConnected {
// 		return isConnected, nil, nil, nil
// 	}
// 	rootIndex := 0
// 	for i := range b1 {
// 		if b1[i] != b2[i] {
// 			break
// 		}
// 		rootIndex = i
// 	}
// 	return isConnected, b1[rootIndex], b1[rootIndex+1:], b2[rootIndex+1:]
// }

func IsConnected(got *ResourcesContainerModel, t1, t2 treeNode) bool {
	return branch(got, t1)[0] == branch(got, t2)[0]
}
func IsVMConnected(got *ResourcesContainerModel, uid1, uid2 string) bool {
	vm1 := got.GetVirtualMachine(uid1)
	vm2 := got.GetVirtualMachine(uid2)
	for v1 := range got.VirtualNetworkInterfaceList {
		vni1 := &got.VirtualNetworkInterfaceList[v1]
		for v2 := range got.VirtualNetworkInterfaceList {
			vni2 := &got.VirtualNetworkInterfaceList[v2]
			if *vni1.OwnerVmId == *vm1.ExternalId && *vni2.OwnerVmId == *vm2.ExternalId {
				if IsConnected(got, vni1, vni2) {
					return true
				}
			}
		}
	}
	return false
}
