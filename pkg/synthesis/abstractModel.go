package synthesis

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type abstractModelSyn struct {
	segments SegmentsToVMs
	groups   GroupsToVMs
	rules    []*abstractRules // with default deny
}

// GroupsWithVMs todo: 1. are the structs group and segment from collector indeed the ones relevant here?
// todo 2. Should the 4 structs below be defined here or in model? should these be computed here or in config?
// todo 3: include entities which are result of a group intersection with a scope? would need a different representation
type GroupsWithVMs struct {
	group *collector.Group
	vms   []*endpoints.VM
}

type GroupsToVMs map[string]GroupsWithVMs

type SegmentsWithVMs struct {
	segment *collector.Segment
	vms     []*endpoints.VM
}

// SegmentsToVMs topology; map from segment name to structs of the segments and its VMs
type SegmentsToVMs map[string]SegmentsWithVMs

type RuleVMs struct {
	vms      []*endpoints.VM
	vmsGroup *collector.Group // nil if vms do not form a group
}

type srcsToDstsConn struct {
	srcVMs RuleVMs
	dstVMs RuleVMs
	conn   *netset.TransportSet
}

// RuleForSynthesis input to synthesis. Synthesis very likely to non-prioritized only allow rules
type RuleForSynthesis struct {
	dfw.FwRule
	// src, dst, scope src as described in the original rule, e.g. segment, service. This is to ease later reference,
	// e.g. in naming the labels
	// todo: is this useful? how broad is collector TreeNode actually? is it suffice? or perhaps
	// just use raw data from collector.Rule? or define an abstract interface?
	abstractSrc   collector.TreeNode
	abstractDst   collector.TreeNode
	abstractScope collector.TreeNode
	// src, dst, conn vms mentioned in the rule that ends up having the rule's action w.r.t. following actual direction
	// this includes the srcVMs implied by the rule that are not override by higher priority rules with opposite act
	// note that a single fwRule may have more than one ruleForSynthesis
	// computed only for allow rules (?)
	actualSrcsToDstsConn []*srcsToDstsConn
}

// todo: will have to combine different categories into a single list of inbound, outbound
type abstractRules struct {
	inbound  []*RuleForSynthesis // ordered list inbound RuleForSynthesis
	outbound []*RuleForSynthesis // ordered list outbound RuleForSynthesis
}
