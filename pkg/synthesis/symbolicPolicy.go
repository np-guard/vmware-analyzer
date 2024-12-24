package synthesis

import (
	"fmt"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

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

/*
func computeAllowOnlyRulesForPolicy(policy *symbolicPolicy) {
	computeAllowOnlyRulesForRules(&policy.inbound)
	computeAllowOnlyRulesForRules(&policy.outbound)
}

func computeAllowOnlyRulesForRules(inboundOrOutbound *[]*symbolicRule) {
	for _, symbolicRule := range *inboundOrOutbound {
		computeAllowOnlyFromRule(symbolicRule, nil, nil)
	}
}

// computes Allow only rules from rule, using the following alg:

func computeAllowOnlyFromRule(symbolicRule *symbolicRule, globalDenies, categoryPasses []*symbolicRule) {
	_, _, _ = symbolicRule, globalDenies, categoryPasses
}
*/
