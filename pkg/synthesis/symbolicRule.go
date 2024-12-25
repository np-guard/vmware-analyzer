package synthesis

import (
	"fmt"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

/////////////////////////////////////////////////////////////////////////////////////
// preprocessing related functionality
/////////////////////////////////////////////////////////////////////////////////////

// todo: one category may have few instances in the original NSX policy; need to chain these to one

// preProcessing: convert policy from spec to symbolicPolicy struct
func preProcessing(categoriesSpecs []*dfw.CategorySpec) (categoryToPolicy map[dfw.DfwCategory]*symbolicPolicy) {
	categoryToPolicy = map[dfw.DfwCategory]*symbolicPolicy{}
	for _, category := range categoriesSpecs {
		categoryPolicy := symbolicPolicy{}
		if len(category.ProcessedRules.Outbound)+len(category.ProcessedRules.Inbound) == 0 {
			continue
		}
		categoryPolicy.inbound = append(categoryPolicy.inbound, convertRulesToSymbolicPaths(category.ProcessedRules.Inbound,
			category.Category)...)
		categoryPolicy.outbound = append(categoryPolicy.outbound, convertRulesToSymbolicPaths(category.ProcessedRules.Outbound,
			category.Category)...)

		categoryToPolicy[category.Category] = &categoryPolicy
	}
	return categoryToPolicy
}

func convertRulesToSymbolicPaths(rules []*dfw.FwRule, category dfw.DfwCategory) []*symbolicRule {
	res := make([]*symbolicRule, len(rules))
	for i, rule := range rules {
		ruleSymbolicPaths := symbolicexpr.ConvertFWRuleToSymbolicPaths(rule)
		res[i] = &symbolicRule{origRule: rule, origRuleCategory: category, origSymbolicPaths: ruleSymbolicPaths}
	}
	return res
}

func (policy symbolicPolicy) string() string {
	return fmt.Sprintf("symbolic inbound rules:\n%v\nsymbolic outbound rules:\n%v", strSymbolicRules(policy.inbound),
		strSymbolicRules(policy.outbound))
}

func strSymbolicRules(rules []*symbolicRule) string {
	resStr := make([]string, len(rules))
	for i, rule := range rules {
		resStr[i] = fmt.Sprintf("\t%v. action: %v paths: %v", i, rule.origRule.Action, rule.origSymbolicPaths)
	}
	return strings.Join(resStr, "\n")
}

func stringCategoryToSymbolicPolicy(categoryToPolicy map[dfw.DfwCategory]*symbolicPolicy) string {
	res := []string{}
	for category, policy := range categoryToPolicy {
		if len(policy.inbound) > 0 || len(policy.outbound) > 0 {
			res = append(res, fmt.Sprintf("category: %s\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v",
				category.String(), policy.string()))
		}
	}
	return strings.Join(res, "\n")
}

/////////////////////////////////////////////////////////////////////////////////////
// convert symbolic rules to allow only functionality
/////////////////////////////////////////////////////////////////////////////////////

func computeAllowOnlyRulesForPolicy(categoriesSpecs []*dfw.CategorySpec,
	categoryToPolicy map[dfw.DfwCategory]*symbolicPolicy) symbolicPolicy {
	allowOnlyPolicy := symbolicPolicy{}
	globalInboundDenies, globalOutboundDenies := symbolicexpr.SymbolicPaths{}, symbolicexpr.SymbolicPaths{}
	// we go over categoriesSpecs to make sure we follow the correct order of categories
	for _, category := range categoriesSpecs {
		thisCategoryPolicy := categoryToPolicy[category.Category]
		if thisCategoryPolicy == nil {
			continue
		}
		inboundAllow, outboundAllow := computeAllowOnlyRulesForCategory(thisCategoryPolicy,
			&globalInboundDenies, &globalOutboundDenies)
		allowOnlyPolicy.inbound = append(allowOnlyPolicy.inbound, inboundAllow...)
		allowOnlyPolicy.outbound = append(allowOnlyPolicy.outbound, outboundAllow...)
		// todo: handle default rule
	}

	return allowOnlyPolicy
}

// gets here only if policy is not nil
func computeAllowOnlyRulesForCategory(originalPolicy *symbolicPolicy, globalInboundDenies,
	globalOutboundDenies *symbolicexpr.SymbolicPaths) (inboundAllowOnly, outboundAllowOnly []*symbolicRule) {
	inboundAllowOnly = computeAllowOnlyInboundOrOutbound(originalPolicy.inbound, globalInboundDenies)
	outboundAllowOnly = computeAllowOnlyInboundOrOutbound(originalPolicy.outbound, globalOutboundDenies)
	return
}

func computeAllowOnlyInboundOrOutbound(originalRules []*symbolicRule, globalDenies *symbolicexpr.SymbolicPaths) []*symbolicRule {
	if originalRules == nil {
		return nil
	}
	newAllows, newDenies := computeAllowOnlyForCategory(&originalRules, globalDenies)
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
func computeAllowOnlyForCategory(inboundOrOutbound *[]*symbolicRule,
	globalDenies *symbolicexpr.SymbolicPaths) (allowRule []*symbolicRule, denyPaths *symbolicexpr.SymbolicPaths) {
	allowOnlyRules := []*symbolicRule{}
	categoryPasses := symbolicexpr.SymbolicPaths{}
	newGlobalDenies := symbolicexpr.SymbolicPaths{}
	copy(newGlobalDenies, *globalDenies)
	for _, rule := range *inboundOrOutbound {
		symbolicDeniesAndPasses := symbolicexpr.SymbolicPaths{}
		switch rule.origRule.Action {
		case dfw.ActionJumpToApp:
			categoryPasses = append(categoryPasses, *rule.origSymbolicPaths...)
		case dfw.ActionDeny:
			newSymbolicPaths := symbolicexpr.ComputeAllowGivenDenies(rule.origSymbolicPaths, &categoryPasses)
			newGlobalDenies = append(newGlobalDenies, *newSymbolicPaths...)
		case dfw.ActionAllow:
			symbolicDeniesAndPasses = append(symbolicDeniesAndPasses, categoryPasses...)
			newSymbolicPaths := symbolicexpr.ComputeAllowGivenDenies(rule.origSymbolicPaths, &symbolicDeniesAndPasses)
			newRule := &symbolicRule{origRule: rule.origRule, origRuleCategory: rule.origRuleCategory,
				origSymbolicPaths: rule.origSymbolicPaths, allowOnlyRulePaths: *newSymbolicPaths}
			allowOnlyRules = append(allowOnlyRules, newRule)
		}
	}
	return allowOnlyRules, &newGlobalDenies
}

func strAllowOnlyPolicy(policy *symbolicPolicy) string {
	return fmt.Sprintf("Allow Only Rules\n~~~~~~~~~~~~~~~~~\ninbound rules\n") +
		strAllowOnlyPathsOfRules(policy.inbound) + fmt.Sprintf("\noutbound rules\n") +
		strAllowOnlyPathsOfRules(policy.outbound)
}

func strAllowOnlyPathsOfRules(rules []*symbolicRule) string {
	res := []string{}
	for _, rule := range rules {
		if rule.allowOnlyRulePaths == nil {
			continue
		}
		for _, path := range rule.allowOnlyRulePaths {
			res = append(res, "\t"+path.String())
		}
	}
	return strings.Join(res, "\n")
}
