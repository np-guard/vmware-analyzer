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
	fmt.Println(stringCategoryToSymbolicPolicy(categoryToPolicy))
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, categoryToPolicy)
	model := &AbstractModelSyn{}
	model.epToGroups = parser.VMsGroups()
	model.policy = append(model.policy, &allowOnlyPolicy)
	return &allowOnlyPolicy, nil
}
