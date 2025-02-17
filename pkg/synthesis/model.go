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
	policy          []*symbolicPolicy // with default deny todo: should be *symbolicPolicy?
	defaultDenyRule *dfw.FwRule
}

// Tags map from tag's name to the tag
type Tags map[string]*collector.Tag

// symbolicRule input to synthesis. Synthesis very likely to non-prioritized only allow policy
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

type symbolicRulePair struct {
	inbound  *symbolicRule // inbound symbolicRule
	outbound *symbolicRule // outbound symbolicRule
}
func (p *symbolicRulePair) aRule()*symbolicRule{
	if p.inbound != nil{
		return p.inbound
	}
	return p.outbound
}

func (p *symbolicRulePair) category() collector.DfwCategory{
	return p.aRule().origRuleCategory
}
func (p *symbolicRulePair) priority() int{
	return p.aRule().origRule.Priority
}
func (p *symbolicRulePair) ruleID() int{
	return p.aRule().origRule.RuleID
}

// a temporary function to get pairs of rules, each pair represent an orig rule.
// to be remove after reorg symbolicPolicy
func (policy *symbolicPolicy) toPairs() []*symbolicRulePair {
	ruleToPair := map[*collector.Rule]*symbolicRulePair{}
	for _, r := range append(policy.inbound, policy.outbound...) {
		ruleToPair[r.origRule.OrigRuleObj] = &symbolicRulePair{}
	}
	for _, r := range policy.inbound {
		ruleToPair[r.origRule.OrigRuleObj].inbound = r
	}
	for _, r := range policy.outbound {
		ruleToPair[r.origRule.OrigRuleObj].outbound = r
	}
	res := slices.Collect(maps.Values(ruleToPair))
	slices.SortStableFunc(res, func(p1, p2 *symbolicRulePair) int {
		switch {
		case p1.category() != p2.category():
			return int(p1.category()) - int(p2.category())
		case p1.priority() != p2.priority():
			return p1.priority() - p2.priority()
		case p1.ruleID() != p2.ruleID():
			return p1.ruleID() - p2.ruleID()
		case p1.inbound != nil:
			return 1
		default:
			return -1
		}
	})
	return res
}

// maps used by AbstractModelSyn

// Segments topology; map from segment name to the segment
type Segments map[string]*collector.Segment
