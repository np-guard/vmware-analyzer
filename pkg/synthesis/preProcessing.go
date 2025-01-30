package synthesis

import (
	"fmt"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

/////////////////////////////////////////////////////////////////////////////////////
// preprocessing related functionality
/////////////////////////////////////////////////////////////////////////////////////

// preProcessing: convert policy from spec to symbolicPolicy struct
func preProcessing(categoriesSpecs []*dfw.CategorySpec) (categoryToPolicy map[collector.DfwCategory]*symbolicPolicy) {
	categoryToPolicy = map[collector.DfwCategory]*symbolicPolicy{}
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

func convertRulesToSymbolicPaths(rules []*dfw.FwRule, category collector.DfwCategory) []*symbolicRule {
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

// prints all symbolic rules by ordered category
// categoriesSpecs []*dfw.CategorySpec is required to have the correct printing order
func stringCategoryToSymbolicPolicy(categoriesSpecs []*dfw.CategorySpec,
	categoryToPolicy map[collector.DfwCategory]*symbolicPolicy) string {
	res := []string{}
	for _, category := range categoriesSpecs {
		policy := categoryToPolicy[category.Category]
		if policy == nil {
			continue
		}
		if len(policy.inbound) > 0 || len(policy.outbound) > 0 {
			res = append(res, fmt.Sprintf("category: %s\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v",
				category.Category.String(), policy.string()))
		}
	}
	return strings.Join(res, "\n")
}
