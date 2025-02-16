package synthesis

import (
	"maps"
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

// AbstractModelSyn is an abstraction from which the synthesis is performed
type AbstractModelSyn struct {
	vms        []*endpoints.VM
	epToGroups map[*endpoints.VM][]*collector.Group
	// todo: add similar maps to OS, hostname

	// if synthesizeAdmin is true, rules will be translated to allow only starting with category MinNonAdminCategory();
	// categories before that category rules' also include pass, deny and priority (default: false - all categories are "Allow only")
	// todo: "JumpTaoApp" -> pass. Not correct in all scenarios, but is good enough for what we need and for POC
	synthesizeAdmin bool
	policy          []*symbolicPolicy // with default deny todo: do we really need an array of []*symbolicPolicy?
	defaultDenyRule *dfw.FwRule
}

// Tags map from tag's name to the tag
type Tags map[string]*collector.Tag

// symbolicRule: rule presentation abstract model. Synthesis very likely to non-prioritized only allow policy
// each inbound and outbound have their []*symbolicRule
//
//nolint:all
type symbolicRule struct { // original rule
	origRule *dfw.FwRule // original rule
	// category; for reference, e.g. in the labels or documentation of the synthesized objects
	// a pass rule is interpreted as deny for the current category
	origRuleCategory  collector.DfwCategory
	origSymbolicPaths *symbolicexpr.SymbolicPaths // symbolic presentation paths defined by the original rule
	// The following refers to conversion of original allow rule to symbolic paths, as follows:
	// Assuming there are only allow (non-prioritized, of course) policy.
	// This is relevant only for allow policy (nil otherwise)
	// and only for categories greater than allowOnlyFromCategory
	allowOnlyRulePaths symbolicexpr.SymbolicPaths
	pathsToSynthesis   *symbolicexpr.SymbolicPaths
}

type symbolicPolicy struct {
	inbound  []*symbolicRule // ordered list inbound symbolicRule
	outbound []*symbolicRule // ordered list outbound symbolicRule
}

// input to k8s synthesis (createK8sResources)
// organized by orig rules and for each orig rule its inbound, outbound rules so that the resulting policy files
// will be consistently ordered by orig rules
type symbolicPolicyForK8sSynthesis []*symbolicRuleByOrig

// symbolicRule: rule input to k8s synthesis (createK8sResources)
// A single entry for each original rule (or none) with both attached inbound and outbound symbolic rules
type symbolicRuleByOrig struct {
	origRule *dfw.FwRule // original rule
	// category; for reference, e.g. in the labels or documentation of the synthesized objects
	// a pass rule is interpreted as deny for the current category
	origRuleCategory  collector.DfwCategory
	origSymbolicPaths *symbolicexpr.SymbolicPaths // symbolic presentation paths defined by the original rule
	// The following refers to conversion of original allow rule to symbolic paths, as follows:
	// Assuming there are only allow (non-prioritized, of course) policy.
	// This is relevant only for allow policy (nil otherwise)
	// and only for categories greater than allowOnlyFromCategory
	allowOnlyInboundPaths  *symbolicexpr.SymbolicPaths
	allowOnlyOutboundPaths *symbolicexpr.SymbolicPaths
}

type symbolicRulePair struct {
	inbound  *symbolicRule // inbound symbolicRule
	outbound *symbolicRule // outbound symbolicRule
}

// a temporary function to get pairs of rules, each pair represent an orig rule.
// to be remove after reorg symbolicPolicy
func (policy *symbolicPolicy) toPairs() []*symbolicRulePair {
	ruleToPair := map[*collector.Rule]*symbolicRulePair{}
	getRulePair := func(r *symbolicRule) *symbolicRulePair {
		if _, ok := ruleToPair[r.origRule.OrigRuleObj]; !ok {
			ruleToPair[r.origRule.OrigRuleObj] = &symbolicRulePair{}
		}
		return ruleToPair[r.origRule.OrigRuleObj]
	}
	for _, r := range policy.inbound {
		getRulePair(r).inbound = r
	}
	for _, r := range policy.outbound {
		getRulePair(r).outbound = r
	}
	res := slices.Collect(maps.Values(ruleToPair))
	slices.SortStableFunc(res, func(p1, p2 *symbolicRulePair) int {
		in1 := slices.Index(policy.inbound, p1.inbound)
		in2 := slices.Index(policy.inbound, p2.inbound)
		out1 := slices.Index(policy.outbound, p1.outbound)
		out2 := slices.Index(policy.outbound, p2.outbound)
		switch {
		case in1 >= 0 && in2 >= 0:
			return in1 - in2
		case out1 >= 0 && out2 >= 0:
			return out1 - out2
		default:
			return 0
		}
	})
	return res
}

// maps used by AbstractModelSyn

// Segments topology; map from segment name to the segment
type Segments map[string]*collector.Segment
