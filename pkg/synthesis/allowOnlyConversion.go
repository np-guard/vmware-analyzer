package synthesis

import (
	"slices"
	"strconv"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

/////////////////////////////////////////////////////////////////////////////////////
// convert symbolic rules to allow only functionality
/////////////////////////////////////////////////////////////////////////////////////

// todo w.r.t. hints *symbolicexpr.Hints at the moment there is no differentiating between tags and groups.
//  There are a few questions here:
//  Is it guaranteed that groups and tags do not have the same name?
//  Does it make sense to define a tag disjoint to a group (or vice versa)?

func computeAllowOnlyRulesForPolicy(categoriesSpecs []*dfw.CategorySpec,
	categoryToPolicy map[collector.DfwCategory]*symbolicPolicy, allowOnlyFromCategory collector.DfwCategory,
	hints *symbolicexpr.Hints) symbolicPolicy {
	computedPolicy := symbolicPolicy{}
	globalInboundDenies, globalOutboundDenies := symbolicexpr.SymbolicPaths{}, symbolicexpr.SymbolicPaths{}
	// we go over categoriesSpecs to make sure we follow the correct order of categories
	for _, category := range categoriesSpecs {
		thisCategoryPolicy := categoryToPolicy[category.Category]
		if thisCategoryPolicy == nil {
			continue
		}
		if category.Category < allowOnlyFromCategory {
			computedPolicy.inbound = append(computedPolicy.inbound, thisCategoryPolicy.inbound...)
			computedPolicy.outbound = append(computedPolicy.outbound, thisCategoryPolicy.outbound...)
			continue
		}
		inboundAllow, outboundAllow := computeAllowOnlyRulesForCategory(thisCategoryPolicy,
			&globalInboundDenies, &globalOutboundDenies, hints)
		computedPolicy.inbound = append(computedPolicy.inbound, inboundAllow...)
		computedPolicy.outbound = append(computedPolicy.outbound, outboundAllow...)
	}
	return computedPolicy
}

// gets here only if policy is not nil
func computeAllowOnlyRulesForCategory(originalPolicy *symbolicPolicy, globalInboundDenies,
	globalOutboundDenies *symbolicexpr.SymbolicPaths, hints *symbolicexpr.Hints) (inboundAllowOnly, outboundAllowOnly []*symbolicRule) {
	inboundAllowOnly = computeAllowOnlyInboundOrOutbound(originalPolicy.inbound, globalInboundDenies, hints)
	outboundAllowOnly = computeAllowOnlyInboundOrOutbound(originalPolicy.outbound, globalOutboundDenies, hints)
	return
}

func computeAllowOnlyInboundOrOutbound(originalRules []*symbolicRule, globalDenies *symbolicexpr.SymbolicPaths,
	hints *symbolicexpr.Hints) []*symbolicRule {
	if originalRules == nil {
		return nil
	}
	newAllows, newDenies := computeAllowOnlyForCategory(&originalRules, globalDenies, hints)
	*globalDenies = append(*globalDenies, *newDenies...)
	return newAllows
}

// computes allow only rules, using the following algorithm:
// For each category, in order:
// Initialization:
//
//	category_passes = empty set
//
// For each rule, in order
//
//	case pass:
//		category_passes = category_passes  or rule
//	case deny:
//		new_denies = merge(category_passes, deny_rule)
//		global_denies = global_denies  union new_denies
//	case allow:
//		new_allow = merge(global_denies or category_passes, allow_rule)
//		global_allows = global_allows  or new_allows
//	Output: global_allows
func computeAllowOnlyForCategory(inboundOrOutbound *[]*symbolicRule, globalDenies *symbolicexpr.SymbolicPaths,
	hints *symbolicexpr.Hints) (allowRule []*symbolicRule, denyPaths *symbolicexpr.SymbolicPaths) {
	allowOnlyRules := []*symbolicRule{}
	categoryPasses := symbolicexpr.SymbolicPaths{}
	newGlobalDenies := slices.Clone(*globalDenies)
	for _, rule := range *inboundOrOutbound {
		switch rule.origRule.Action {
		case dfw.ActionJumpToApp:
			categoryPasses = append(categoryPasses, *rule.origSymbolicPaths...)
		case dfw.ActionDeny:
			newSymbolicPaths := symbolicexpr.ComputeAllowGivenDenies(rule.origSymbolicPaths, &categoryPasses, hints)
			newGlobalDenies = append(newGlobalDenies, *newSymbolicPaths...)
		case dfw.ActionAllow:
			symbolicDeniesAndPasses := slices.Clone(newGlobalDenies)
			symbolicDeniesAndPasses = append(symbolicDeniesAndPasses, categoryPasses...)
			newSymbolicPaths := symbolicexpr.ComputeAllowGivenDenies(rule.origSymbolicPaths, &symbolicDeniesAndPasses, hints)
			newRule := &symbolicRule{origRule: rule.origRule, origRuleCategory: rule.origRuleCategory,
				origSymbolicPaths: rule.origSymbolicPaths, allowOnlyRulePaths: *newSymbolicPaths}
			allowOnlyRules = append(allowOnlyRules, newRule)
		}
	}
	return allowOnlyRules, &newGlobalDenies
}

func strAllowOnlyPolicy(policy *symbolicPolicy, color bool) string {
	return "Allow Only Rules\n~~~~~~~~~~~~~~~~~\ninbound rules\n" +
		strAllowOnlyPathsOfRules(policy.inbound, color) + "outbound rules\n" +
		strAllowOnlyPathsOfRules(policy.outbound, color)
}

func strAllowOnlyPathsOfRules(rules []*symbolicRule, color bool) string {
	header := []string{"original allow rule index", "Src", "Dst", "Connection"}
	lines := [][]string{}
	for i, rule := range rules {
		if rule.allowOnlyRulePaths == nil {
			continue
		}
		for _, path := range rule.allowOnlyRulePaths {
			newLine := append([]string{strconv.Itoa(i)}, path.TableString()...)
			lines = append(lines, newLine)
		}
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}
