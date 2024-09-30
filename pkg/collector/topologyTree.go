/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector


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
func (s *Segment) name() string                 { return *s.DisplayName + "(sg)" }
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

