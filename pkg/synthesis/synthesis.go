package synthesis

import (
	"fmt"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
)

func NSXSynthesis(recourses *collector.ResourcesContainerModel, params model.OutputParameters) (string, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return "", err
	}
	config := parser.GetConfig()

	// in debug/verbose mode -- print the parsed config
	// logging.Debugf("the parsed config details: %s", config.GetConfigInfoStr())

	fmt.Println("list of groups")
	for _, group := range (*recourses).DomainList[0].Resources.GroupList {
		fmt.Printf("group is %v\n", group.Name())
	}

	// the following code is temp; just access relevant data
	fmt.Println("list of VMs\n===========")
	for i, vm := range config.Vms {
		fmt.Printf("\t%v. %v\n", i, vm.Name())
	}

	fmt.Println("\nlist of categories\n==============")
	for _, category := range config.Fw.CategoriesSpecs {
		if len(category.ProcessedRules.Outbound)+len(category.ProcessedRules.Inbound) == 0 {
			fmt.Printf("no rules in category %v\n", category.Category)
			continue
		}
		fmt.Printf("\ncategory: %v\n===============\n", category.Category)
		tmpAddSymbolicSrcDstRules(category.ProcessedRules.Outbound)
		tmpAddSymbolicSrcDstRules(category.ProcessedRules.Inbound)
	}
	return "", nil
}

func tmpAddSymbolicSrcDstRules(rules []*dfw.FwRule) {
	for _, rule := range rules {
		origRule := rule.OrigRuleObj
		fmt.Printf("\nruleId %v action %v\n~~~~~~~~~~~~~~~~~~~~~~\nsourceGroups: \n", *origRule.RuleId, rule.Action)
		tmpPrintGroup(origRule.SourceGroups)
		fmt.Println("\nDestinationGroups:")
		tmpPrintGroup(origRule.DestinationGroups)
		fmt.Println()
	}
}

func tmpPrintGroup(group []string) {
	for _, destinationGroup := range group {
		fmt.Printf("\t\t%v ", destinationGroup)
	}
}
