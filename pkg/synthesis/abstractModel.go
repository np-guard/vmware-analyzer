package synthesis

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type srcDstVM struct {
	srcVM *endpoints.VM
	dstVM *endpoints.VM
}

// SegmentsToVMs topology
type SegmentsToVMs map[string][]*endpoints.VM

// RuleForSynthesis input to synthesis. Synthesis very likely to non-prioritized only allow rules
type RuleForSynthesis struct {
	dfw.FwRule
	// src, dst, scope src as described in the original rule, e.g. segment, service. This is to ease later reference,
	// e.g. in naming the labels
	// todo: is this useful? how broad is collector TreeNode actually? is it suffice? or perhaps
	// just use raw data from collector.Rule?
	abstractSrc   collector.TreeNode
	abstractDst   collector.TreeNode
	abstractScope collector.TreeNode
	// src, dst, conn vms mentioned in the rule that ends up having the rule's action w.r.t. following actual direction
	// this includes the srcVMs implied by the rule that are not override by higher priority rules with opposite act
	// note that a single fwRule may have more than one ruleForSynthesis
	actualSrcVMs    []*endpoints.VM
	actualDstVms    []*endpoints.VM
	actualConn      *netset.TransportSet
	actualDirection string
	// single src to single dst enabled by this rule, not covered by the above actualSrcVMs, actualDstVms
	// to be used for <src, dst> pairs that can not be described by actualSrcVMs and actualDstVms due to higher priority
	// overriding rules; note that this is relevant only when |actualSrcVMs| > 1, |actualDstVms|>1 and there are higher
	// priority  overriding rules
	actualSrcDstVM srcDstVM
}
