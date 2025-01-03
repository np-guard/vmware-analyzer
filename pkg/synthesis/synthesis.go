package synthesis

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

func NSXToAbstractModelSynthesis(recourses *collector.ResourcesContainerModel) (*symbolicPolicy, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	fmt.Println(stringCategoryToSymbolicPolicy(config.Fw.CategoriesSpecs, categoryToPolicy))
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, categoryToPolicy)
	return &allowOnlyPolicy, nil
}
