package synthesis

import (
	"fmt"
	"strconv"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
)

/////////////////////////////////////////////////////////////////////////////////////
// preprocessing related functionality
/////////////////////////////////////////////////////////////////////////////////////

// preProcessing: convert policy from spec to symbolicPolicy struct
func preProcessing(categoriesSpecs []*dfw.CategorySpec) (categoryToPolicy map[collector.DfwCategory]*symbolicPolicy) {
	categoryToPolicy = map[collector.DfwCategory]*symbolicPolicy{}
	groupToConjunctions := map[string][]*symbolicexpr.Conjunction{} // caching groups' Conjunctions
	for _, category := range categoriesSpecs {
		categoryPolicy := symbolicPolicy{}
		if len(category.ProcessedRules.Outbound)+len(category.ProcessedRules.Inbound) == 0 {
			continue
		}
		categoryPolicy.inbound = append(categoryPolicy.inbound, convertRulesToSymbolicPaths(category.ProcessedRules.Inbound,
			category.Category, groupToConjunctions)...)
		categoryPolicy.outbound = append(categoryPolicy.outbound, convertRulesToSymbolicPaths(category.ProcessedRules.Outbound,
			category.Category, groupToConjunctions)...)

		categoryToPolicy[category.Category] = &categoryPolicy
	}
	return categoryToPolicy
}

func convertRulesToSymbolicPaths(rules []*dfw.FwRule, category collector.DfwCategory,
	groupToConjunctions map[string][]*symbolicexpr.Conjunction) []*symbolicRule {
	res := make([]*symbolicRule, len(rules))
	for i, rule := range rules {
		ruleSymbolicPaths := symbolicexpr.ConvertFWRuleToSymbolicPaths(rule, groupToConjunctions)
		res[i] = &symbolicRule{origRule: rule, origRuleCategory: category, origSymbolicPaths: ruleSymbolicPaths}
	}
	return res
}

func (policy symbolicPolicy) strOrigSymbolicPolicy(printOnlyAdmin, color bool) string {
	return fmt.Sprintf("symbolic inbound rules:\n%v\nsymbolic outbound rules:\n%v",
		strOrigSymbolicRules(policy.inbound, printOnlyAdmin, color),
		strOrigSymbolicRules(policy.outbound, printOnlyAdmin, color))
}

func strOrigSymbolicRules(rules []*symbolicRule, printOnlyAdmin, color bool) string {
	header := []string{"Priority", "Action", "Src", "Dst", "Connection"}
	lines := [][]string{}
	for i, rule := range rules {
		for _, path := range *rule.origSymbolicPaths {
			if printOnlyAdmin && !(rule.origRuleCategory < collector.MinNonAdminCategory()) {
				continue
			}
			newLine := append([]string{strconv.Itoa(i), string(rule.origRule.Action)},
				path.TableString()...)
			lines = append(lines, newLine)
		}
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}

// prints pre-processing symbolic rules by ordered category;
// with an option to print only the subset that will be synthesized to admin rules
// categoriesSpecs []*dfw.CategorySpec is required to have the correct printing order
func printPreProcessingSymbolicPolicy(categoriesSpecs []*dfw.CategorySpec,
	categoryToPolicy map[collector.DfwCategory]*symbolicPolicy, color bool) string {
	var categoryToStr = func(c *dfw.CategorySpec) string {
		policy := categoryToPolicy[c.Category]
		if policy == nil {
			return ""
		}
		return fmt.Sprintf("category: %s\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%s", c.Category.String(),
			policy.strOrigSymbolicPolicy(false, color))
	}
	return common.JoinCustomStrFuncSlice(categoriesSpecs, categoryToStr, common.NewLine)
}
