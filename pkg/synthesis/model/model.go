package model

import (
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

// AbstractModelSyn is an abstraction from which the synthesis is performed
type AbstractModelSyn struct {
	Config               *configuration.Config
	VMs                  []topology.Endpoint
	Segments             []*topology.Segment
	AllGroups            []*collector.Group      // todo - should we need it?
	AllRuleIPBlocks      []*topology.RuleIPBlock // todo - should we need it?
	EndpointsToGroups    map[topology.Endpoint][]*collector.Group
	RuleBlockPerEndpoint map[topology.Endpoint][]*topology.RuleIPBlock
	VMsSegments          map[topology.Endpoint][]*topology.Segment
	ExternalIP           *netset.IPBlock
	// todo: add similar maps to OS, hostname

	// if SynthesizeAdmin is true, rules will be translated to allow only starting with category MinNonAdminCategory();
	// categories before that category rules' also include pass, deny and priority (default: false - all categories are "Allow only")
	// todo: "JumpTaoApp" -> pass. Not correct in all scenarios, but is good enough for what we need and for POC
	SynthesizeAdmin bool
	Policy          []*SymbolicPolicy // with default deny todo: should be *symbolicPolicy?
	DefaultDenyRule *dfw.FwRule
}

// SymbolicRule input to synthesis. Synthesis very likely to non-prioritized only allow policy
//
//nolint:all
type SymbolicRule struct { // original rule
	OrigRule *dfw.FwRule // original rule
	// category; for reference, e.g. in the labels or documentation of the synthesized objects
	// a pass rule is interpreted as deny for the current category
	OrigRuleCategory  collector.DfwCategory
	OrigSymbolicPaths *symbolicexpr.SymbolicPaths // symbolic presentation paths defined by the original rule
	// The following refers to conversion of original allow rule to symbolic paths, as follows:
	// Assuming there are only allow (non-prioritized, of course) policy.
	// This is relevant only for allow policy (nil otherwise)
	// and only for categories greater than allowOnlyFromCategory
	allowOnlyRulePaths symbolicexpr.SymbolicPaths
	// allow only list after optimization in global scope - e.g. a path is removed if there is a path in another
	// rule that is a super set of it.
	// In case of two identical paths - the paths stays in the higher priority rule
	OptimizedAllowOnlyPaths symbolicexpr.SymbolicPaths
}

func (r *SymbolicRule) category() collector.DfwCategory {
	return r.OrigRuleCategory
}
func (r *SymbolicRule) priority() int {
	return r.OrigRule.Priority
}
func (r *SymbolicRule) ruleID() int {
	return r.OrigRule.RuleID
}

type SymbolicPolicy struct {
	Inbound  []*SymbolicRule // ordered list inbound symbolicRule
	Outbound []*SymbolicRule // ordered list outbound symbolicRule
}

func (policy *SymbolicPolicy) IsInbound(r *SymbolicRule) bool {
	return slices.Contains(policy.Inbound, r)
}

// sorting the policies before synthesis, for the user to be intuitive:
// by categories, by priority, by rule Id, etc...
func (policy *SymbolicPolicy) SortRules() []*SymbolicRule {
	symbolicOrigRulesSortFunc := func(r1, r2 *SymbolicRule) int {
		switch {
		case r1.category() != r2.category():
			return int(r1.category()) - int(r2.category())
		case r1.priority() != r2.priority():
			return r1.priority() - r2.priority()
		case r1.ruleID() != r2.ruleID():
			return r1.ruleID() - r2.ruleID()
		case policy.IsInbound(r1):
			return 1
		default:
			return -1
		}
	}
	res := slices.Concat(policy.Inbound, policy.Outbound)
	slices.SortStableFunc(res, symbolicOrigRulesSortFunc)
	return res
}

func StrAbstractModel(abstractModel *AbstractModelSyn, options *config.SynthesisOptions) string {
	return "\nAbstract Model Details\n=======================\n" +
		strGroups(abstractModel.Config, options.Color) + strAdminPolicy(abstractModel.Policy[0], options) +
		strAllowOnlyPolicy(abstractModel.Policy[0], options.Color)
}

func strAdminPolicy(policy *SymbolicPolicy, options *config.SynthesisOptions) string {
	if !options.SynthesizeAdmin {
		return ""
	}
	return "Admin policy rules\n~~~~~~~~~~~~~~~~~~\ninbound rules\n" +
		strOrigSymbolicRules(policy.Inbound, true, options.Color) + "outbound rules\n" +
		strOrigSymbolicRules(policy.Outbound, true, options.Color)
}

func strGroups(nsxConfig *configuration.Config, color bool) string {
	return "\nGroups' definition\n~~~~~~~~~~~~~~~~~~\n" + nsxConfig.GetGroupsStr(color)
}
