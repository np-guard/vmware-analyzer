package model

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

/////////////////////////////////////////////////////////////////////////////////////
// preprocessing related functionality
/////////////////////////////////////////////////////////////////////////////////////

// PreProcessing convert policy from spec to symbolicPolicy struct
func PreProcessing(config *configuration.Config,
	categoriesSpecs []*dfw.CategorySpec) (categoryToPolicy map[collector.DfwCategory]*SymbolicPolicy,
	groupToDNF map[string]symbolicexpr.DNF) {
	categoryToPolicy = map[collector.DfwCategory]*SymbolicPolicy{}
	groupToDNF = map[string]symbolicexpr.DNF{} // caching groups' DNFs
	for _, category := range categoriesSpecs {
		categoryPolicy := SymbolicPolicy{}
		if len(category.EvaluatedRules.OutboundRules)+len(category.EvaluatedRules.InboundRules) == 0 {
			continue
		}
		categoryPolicy.Inbound = append(categoryPolicy.Inbound, convertRulesToSymbolicPaths(config, true,
			category.EvaluatedRules.InboundRules, category.Category, groupToDNF)...)
		categoryPolicy.Outbound = append(categoryPolicy.Outbound, convertRulesToSymbolicPaths(config, false,
			category.EvaluatedRules.OutboundRules, category.Category, groupToDNF)...)

		categoryToPolicy[category.Category] = &categoryPolicy
	}
	return categoryToPolicy, groupToDNF
}

func convertRulesToSymbolicPaths(config *configuration.Config, isInbound bool,
	rules []*dfw.EvaluatedFWRule, category collector.DfwCategory,
	groupToDNF map[string]symbolicexpr.DNF) []*SymbolicRule {
	res := make([]*SymbolicRule, len(rules))
	for i, rule := range rules {
		ruleSymbolicPaths := symbolicexpr.ConvertFWRuleToSymbolicPaths(config, isInbound, rule.RuleObj, groupToDNF)
		res[i] = &SymbolicRule{OrigRule: rule.RuleObj, OrigRuleCategory: category, OrigSymbolicPaths: ruleSymbolicPaths}
	}
	return res
}

func (policy SymbolicPolicy) strOrigSymbolicPolicy(printOnlyAdmin, color bool) string {
	return fmt.Sprintf("symbolic inbound rules:\n%v\nsymbolic outbound rules:\n%v",
		strOrigSymbolicRules(policy.Inbound, printOnlyAdmin, color),
		strOrigSymbolicRules(policy.Outbound, printOnlyAdmin, color))
}

func strOrigSymbolicRules(rules []*SymbolicRule, printOnlyAdmin, color bool) string {
	header := []string{"Priority", "Rule Id", "Action", "Src", "Dst", "Connection"}
	lines := [][]string{}
	const formatV = "%v"
	for i, rule := range rules {
		for _, path := range *rule.OrigSymbolicPaths {
			if printOnlyAdmin && rule.OrigRuleCategory >= collector.MinNonAdminCategory() {
				continue
			}
			newLine := []string{fmt.Sprintf(formatV, i), rule.OrigRule.RuleIDStr(),
				fmt.Sprintf(formatV, rule.OrigRule.Action)}
			newLine = append(newLine, path.TableString()...)
			lines = append(lines, newLine)
		}
	}
	return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}

// PrintPreProcessingSymbolicPolicy prints pre-processing symbolic rules by ordered category;
// with an option to print only the subset that will be synthesized to admin rules
// categoriesSpecs []*dfw.CategorySpec is required to have the correct printing order
func PrintPreProcessingSymbolicPolicy(categoriesSpecs []*dfw.CategorySpec,
	categoryToPolicy map[collector.DfwCategory]*SymbolicPolicy, color bool) string {
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
