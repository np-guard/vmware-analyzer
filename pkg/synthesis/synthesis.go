package synthesis

import (
	"fmt"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"strings"
)

func NSXSynthesis(recourses *collector.ResourcesContainerModel, params model.OutputParameters) (string, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return "", err
	}
	config := parser.GetConfig()
	for _, category := range config.Fw.CategoriesSpecs {
		if len(category.ProcessedRules.Outbound)+len(category.ProcessedRules.Inbound) == 0 {
			fmt.Printf("no rules in category %v\n", category.Category)
			continue
		}
		fmt.Printf("\ncategory: %v\n===============\n", category.Category)
		fmt.Println("Outbound rules:")
		printRules(category.ProcessedRules.Outbound)
		fmt.Println("Inbound rules:")
		printRules(category.ProcessedRules.Inbound)
	}
	return "", nil
}

func printRules(rules []*dfw.FwRule) {
	for _, rule := range rules {
		fmt.Printf("\taction %v SourceGroups: %v DestinationGroups: %v\n", rule.Action,
			getGroupsStr(rule.SrcGroups, rule.IsAllSrcGroups), getGroupsStr(rule.DstGroups, rule.IsAllDstGroups))
	}
}

func getGroupsStr(groups []*collector.Group, isAll bool) string {
	if isAll {
		return "Any"
	}
	groupsStr := make([]string, len(groups))
	for i, group := range groups {
		groupsStr[i] = *group.DisplayName
	}
	return strings.Join(groupsStr, ", ")
}
