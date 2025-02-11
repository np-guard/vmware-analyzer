package synthesis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
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
	groupToConjunctions := map[string][]*symbolicexpr.Conjunction{} //cashing groups' Conjunctions
	for i, rule := range rules {
		ruleSymbolicPaths := symbolicexpr.ConvertFWRuleToSymbolicPaths(rule, groupToConjunctions)
		res[i] = &symbolicRule{origRule: rule, origRuleCategory: category, origSymbolicPaths: ruleSymbolicPaths}
	}
	return res
}

func (policy symbolicPolicy) string(color bool) string {
	return fmt.Sprintf("symbolic inbound rules:\n%v\nsymbolic outbound rules:\n%v", strSymbolicRules(policy.inbound, color),
		strSymbolicRules(policy.outbound, color))
}

func strSymbolicRules(rules []*symbolicRule, color bool) string {
	header := []string{"Priority", "Action", "Src", "Dst", "Connection"}
	lines := [][]string{}
	for i, rule := range rules {
		for _, path := range *rule.origSymbolicPaths {
			newLine := append([]string{strconv.Itoa(i), string(rule.origRule.Action)},
				path.TableString()...)
			lines = append(lines, newLine)
		}
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}

// prints pre-processing symbolic rules by ordered category
// categoriesSpecs []*dfw.CategorySpec is required to have the correct printing order
func printPreProcessingSymbolicPolicy(categoriesSpecs []*dfw.CategorySpec,
	categoryToPolicy map[collector.DfwCategory]*symbolicPolicy, color bool) string {
	res := []string{}
	for _, category := range categoriesSpecs {
		policy := categoryToPolicy[category.Category]
		if policy == nil {
			continue
		}
		if len(policy.inbound) > 0 || len(policy.outbound) > 0 {
			res = append(res, fmt.Sprintf("category: %s\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v",
				category.Category.String(), policy.string(color)))
		}
	}
	return strings.Join(res, "\n")
}
