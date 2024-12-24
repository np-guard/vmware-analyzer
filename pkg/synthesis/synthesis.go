package synthesis

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

func NSXSynthesis(recourses *collector.ResourcesContainerModel, params model.OutputParameters) (string, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return "", err
	}
	config := parser.GetConfig()
	policy := preProcessing(config.Fw.CategoriesSpecs)
	//computeAllowOnlyRulesForPolicy(policy)
	fmt.Println(policy.string())
	return "", nil
}

// todo: output should be  (categoryToPolicy map[dfw.DfwCategory]*symbolicPolicy)
// preProcessing: convert policy from spec to symbolicPolicy struct
func preProcessing(categoriesSpecs []*dfw.CategorySpec) (policy symbolicPolicy) {
	policy = symbolicPolicy{}
	for _, category := range categoriesSpecs {
		if len(category.ProcessedRules.Outbound)+len(category.ProcessedRules.Inbound) == 0 {
			continue
		}
		policy.inbound = append(policy.inbound, convertRulesToSymbolicPaths(category.ProcessedRules.Inbound,
			category.Category)...)
		policy.outbound = append(policy.outbound, convertRulesToSymbolicPaths(category.ProcessedRules.Outbound,
			category.Category)...)
	}
	return policy
}

func convertRulesToSymbolicPaths(rules []*dfw.FwRule, category dfw.DfwCategory) []*symbolicRule {
	res := make([]*symbolicRule, len(rules))
	for i, rule := range rules {
		ruleSymbolicPaths := symbolicexpr.ConvertFWRuleToSymbolicPaths(rule)
		res[i] = &symbolicRule{origRule: rule, origRuleCategory: category, origSymbolicPaths: ruleSymbolicPaths}
	}
	return res
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
