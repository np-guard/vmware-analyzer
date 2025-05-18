package model

import (
	"fmt"
	"slices"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

/////////////////////////////////////////////////////////////////////////////////////
// convert symbolic rules to allow only functionality
/////////////////////////////////////////////////////////////////////////////////////

// todo w.r.t. hints *symbolicexpr.Hints at the moment there is no differentiating between tags and groups.
//  There are a few questions here:
//  Is it guaranteed that groups and tags do not have the same name?
//  Does it make sense to define a tag disjoint to a group (or vice versa)?

func ComputeAllowOnlyRulesForPolicy(categoriesSpecs []*dfw.CategorySpec,
	categoryToPolicy map[collector.DfwCategory]*SymbolicPolicy, synthesizeAdmin bool,
	hints *symbolicexpr.Hints) SymbolicPolicy {
	computedPolicy := SymbolicPolicy{}
	globalInboundDenies, globalOutboundDenies := symbolicexpr.SymbolicPaths{}, symbolicexpr.SymbolicPaths{}
	// we go over categoriesSpecs to make sure we follow the correct order of categories
	for _, category := range categoriesSpecs {
		thisCategoryPolicy := categoryToPolicy[category.Category]
		if thisCategoryPolicy == nil {
			continue
		}
		if synthesizeAdmin && category.Category < collector.MinNonAdminCategory() {
			computedPolicy.Inbound = append(computedPolicy.Inbound, thisCategoryPolicy.Inbound...)
			computedPolicy.Outbound = append(computedPolicy.Outbound, thisCategoryPolicy.Outbound...)
			continue
		}
		inboundAllow, outboundAllow := computeAllowOnlyRulesForCategory(thisCategoryPolicy,
			&globalInboundDenies, &globalOutboundDenies, hints)
		computedPolicy.Inbound = append(computedPolicy.Inbound, inboundAllow...)
		computedPolicy.Outbound = append(computedPolicy.Outbound, outboundAllow...)
	}
	return computedPolicy
}

// gets here only if policy is not nil
func computeAllowOnlyRulesForCategory(originalPolicy *SymbolicPolicy, globalInboundDenies,
	globalOutboundDenies *symbolicexpr.SymbolicPaths, hints *symbolicexpr.Hints) (inboundAllowOnly, outboundAllowOnly []*SymbolicRule) {
	inboundAllowOnly = computeAllowOnlyInboundOrOutbound(true, originalPolicy.Inbound, globalInboundDenies, hints)
	outboundAllowOnly = computeAllowOnlyInboundOrOutbound(false, originalPolicy.Outbound, globalOutboundDenies, hints)
	return
}

func computeAllowOnlyInboundOrOutbound(isInbound bool, originalRules []*SymbolicRule,
	globalDenies *symbolicexpr.SymbolicPaths, hints *symbolicexpr.Hints) []*SymbolicRule {
	if originalRules == nil {
		return nil
	}
	newAllows, newDenies := computeAllowOnlyForCategory(isInbound, &originalRules, globalDenies, hints)
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
func computeAllowOnlyForCategory(isInbound bool, inboundOrOutbound *[]*SymbolicRule, globalDenies *symbolicexpr.SymbolicPaths,
	hints *symbolicexpr.Hints) (allowRule []*SymbolicRule, denyPaths *symbolicexpr.SymbolicPaths) {
	allowOnlyRules := []*SymbolicRule{}
	categoryPasses := symbolicexpr.SymbolicPaths{}
	newGlobalDenies := slices.Clone(*globalDenies)
	for _, rule := range *inboundOrOutbound {
		switch rule.OrigRule.Action {
		case dfw.ActionJumpToApp:
			categoryPasses = append(categoryPasses, *rule.OrigSymbolicPaths...)
		case dfw.ActionDeny:
			newSymbolicPaths := symbolicexpr.ComputeAllowGivenDenies(isInbound, rule.OrigSymbolicPaths, &categoryPasses, hints)
			newGlobalDenies = append(newGlobalDenies, *newSymbolicPaths...)
		case dfw.ActionAllow:
			symbolicDeniesAndPasses := slices.Clone(newGlobalDenies)
			symbolicDeniesAndPasses = append(symbolicDeniesAndPasses, categoryPasses...)
			newSymbolicPaths := symbolicexpr.ComputeAllowGivenDenies(isInbound, rule.OrigSymbolicPaths,
				&symbolicDeniesAndPasses, hints)
			newRule := &SymbolicRule{OrigRule: rule.OrigRule, OrigRuleCategory: rule.OrigRuleCategory,
				OrigSymbolicPaths: rule.OrigSymbolicPaths, allowOnlyRulePaths: *newSymbolicPaths,
				OptimizedAllowOnlyPaths: symbolicexpr.SymbolicPaths{}}
			allowOnlyRules = append(allowOnlyRules, newRule)
		}
	}
	return allowOnlyRules, &newGlobalDenies
}

func OptimizeSymbolicPolicy(policy *SymbolicPolicy, options *config.SynthesisOptions) *SymbolicPolicy {
	optimizedInbound := optimizeSymbolicRules(policy.Inbound, options)
	optimizedOutbound := optimizeSymbolicRules(policy.Outbound, options)
	return &SymbolicPolicy{Inbound: optimizedInbound, Outbound: optimizedOutbound}
}

// given a list of inbound/outbound symbolicRules optimizes the rules in the global scope: namely, removes
// symbolic paths that are subsets of other symbolic paths
// if a specific symbolic path was present in multiple symbolicRules, we will keep it only in the rule with the lowest
// index (which implies higher priority)
func optimizeSymbolicRules(rules []*SymbolicRule, options *config.SynthesisOptions) []*SymbolicRule {
	// 1. gathers all symbolicPaths, keeps a pointer from each path to its symbolic rule (or to the "lowest" one as above)
	var allSymbolicPath symbolicexpr.SymbolicPaths
	var symbolicPathToRule = map[string]int{}
	for i, rule := range rules {
		for _, path := range rule.allowOnlyRulePaths {
			key := path.String()
			if _, exist := symbolicPathToRule[key]; exist {
				continue // if a path appears in several rules, takes and remember the 1st
			}
			allSymbolicPath = append(allSymbolicPath, path)
			symbolicPathToRule[key] = i
		}
	}
	// 2. Optimizes symbolic paths
	optimizedPaths := allSymbolicPath.RemoveIsSubsetPath(options.Hints)
	// 3. Updated list of optimized symbolicRules
	// 3.1 Creates of set of indexes of rules that have at least one path in the optimized list, and thus should be
	// in the final list of optimized rules
	ruleInOptimize := make(map[int]bool, len(rules))
	for _, path := range optimizedPaths {
		ruleInOptimize[symbolicPathToRule[path.String()]] = true
	}
	// 3.1 create a list of the optimized rules, optimizedAllowOnlyPaths yet to be updated
	var optimizedRules []*SymbolicRule
	var oldToNewIndexes = make(map[int]int, len(rules))
	for i, rule := range rules {
		newIndx := -1
		if ruleInOptimize[i] {
			newIndx = len(optimizedRules)
			optimizedRules = append(optimizedRules, rule)
			// keep admin policy rules, which are not part of the optimization
		} else if options.SynthesizeAdmin && rule.OrigRuleCategory < collector.MinNonAdminCategory() {
			optimizedRules = append(optimizedRules, rule)
		}
		oldToNewIndexes[i] = newIndx
	}
	// 3.2 updates optimizedAllowOnlyPaths in their rules
	for _, path := range optimizedPaths {
		oldIndex := symbolicPathToRule[path.String()]
		newIndex := oldToNewIndexes[oldIndex]
		pathsOfOptimizedRule := optimizedRules[newIndex].OptimizedAllowOnlyPaths
		pathsOfOptimizedRule = append(pathsOfOptimizedRule, path)
		optimizedRules[newIndex].OptimizedAllowOnlyPaths = pathsOfOptimizedRule
	}
	return optimizedRules
}

func strAllowOnlyPolicy(policy *SymbolicPolicy, color bool) string {
	return "\nAllow Only Rules\n~~~~~~~~~~~~~~~~~\ninbound rules\n" +
		strAllowOnlyPathsOfRules(policy.Inbound, color) + "outbound rules\n" +
		strAllowOnlyPathsOfRules(policy.Outbound, color)
}

func strAllowOnlyPathsOfRules(rules []*SymbolicRule, color bool) string {
	header := []string{"Original allow rule priority", "Rule id", "Src", "Dst", "Connection"}
	lines := [][]string{}
	for i, rule := range rules {
		if rule.OptimizedAllowOnlyPaths == nil {
			continue
		}
		for _, path := range rule.OptimizedAllowOnlyPaths {
			newLine := []string{fmt.Sprintf("%v", i), rule.OrigRule.RuleIDStr()}
			newLine = append(newLine, path.TableString()...)
			lines = append(lines, newLine)
		}
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}
