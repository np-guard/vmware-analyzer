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
	symbolicRules := symbolicRules{}
	symbolicRules.inbound, symbolicRules.outbound = preProcessing(config.Fw.CategoriesSpecs)
	fmt.Println(symbolicRules.string())
	return "", nil
}

// preProcessing: convert rules from spec to symbolicRules struct
func preProcessing(categoriesSpecs []*dfw.CategorySpec) (inbound, outbound []*SymbolicRule) {
	for _, category := range categoriesSpecs {
		if len(category.ProcessedRules.Outbound)+len(category.ProcessedRules.Inbound) == 0 {
			continue
		}
		inbound = append(inbound, convertRulesToSymbolicPaths(category.ProcessedRules.Inbound, category.Category)...)
		outbound = append(outbound, convertRulesToSymbolicPaths(category.ProcessedRules.Outbound, category.Category)...)
	}
	return inbound, outbound
}

func convertRulesToSymbolicPaths(rules []*dfw.FwRule, category dfw.DfwCategory) []*SymbolicRule {
	res := make([]*SymbolicRule, len(rules))
	for i, rule := range rules {
		ruleSymbolicPaths := symbolicexpr.ConvertFWRuleToSymbolicPaths(rule)
		res[i] = &SymbolicRule{origRule: rule, origRuleCategory: category, origSymbolicPaths: ruleSymbolicPaths}
	}
	return res
}
