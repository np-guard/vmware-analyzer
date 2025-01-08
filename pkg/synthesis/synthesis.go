package synthesis

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

func NSXToAbstractModelSynthesis(recourses *collector.ResourcesContainerModel,
	hints *symbolicexpr.Hints) (*symbolicPolicy, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	fmt.Println(stringCategoryToSymbolicPolicy(config.Fw.CategoriesSpecs, categoryToPolicy))
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, categoryToPolicy, hints)
	abstractModel := &AbstractModelSyn{}
	abstractModel.epToGroups = parser.VMsGroups()
	abstractModel.vms = parser.VMs()
	abstractModel.policy = append(abstractModel.policy, &allowOnlyPolicy)
	return &allowOnlyPolicy, nil
}
