/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

type treeNode interface {
	parent(resources *ResourcesContainerModel) treeNode
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
func (segment *Segment) parent(resources *ResourcesContainerModel) treeNode {
	if segment.ConnectivityPath == nil {
		return nil
	}
	if t1 := resources.GetTier1(*segment.ConnectivityPath); t1 != nil {
		return t1
	}
	return resources.GetTier0(*segment.ConnectivityPath)
}
func (t *Tier1) parent(resources *ResourcesContainerModel) treeNode {
	return resources.GetTier0(*t.Tier0Path)
}
func (t *Tier0) parent(resources *ResourcesContainerModel) treeNode { return nil }

// //////////////////////////////////////////////////////////////////////
type treeNodeBranch []treeNode

func branch(resources *ResourcesContainerModel, n treeNode) treeNodeBranch {
	if n == nil {
		return treeNodeBranch{}
	}
	p := n.parent(resources)
	return append(branch(resources, p), n)
}

//nolint:nonamedreturns // god, please give me the wisdom to understand thant "named return isConnected with type bool found" means
func treeNodesPath(got *ResourcesContainerModel, t1, t2 treeNode) (isConnected bool, root treeNode, b1, b2 treeNodeBranch) {
	b1 = branch(got, t1)
	b2 = branch(got, t2)
	isConnected = b1[0] == b2[0]
	if !isConnected {
		return isConnected, nil, nil, nil
	}
	rootIndex := 0
	for i := range b1 {
		if b1[i] != b2[i] {
			break
		}
		rootIndex = i
	}
	return isConnected, b1[rootIndex], b1[rootIndex+1:], b2[rootIndex+1:]
}

func IsConnected(got *ResourcesContainerModel, t1, t2 treeNode) bool {
	//nolint:dogsled // I have no idea how to fix such case. is there other way to call the method and  use only one of the returns value?!?!
	c, _, _, _ := treeNodesPath(got, t1, t2)
	return c
}
