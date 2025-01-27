package synthesis

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

func NSXToK8sSynthesis(
	recourses *collector.ResourcesContainerModel,
	outDir string,
	hints *symbolicexpr.Hints, allowOnlyFromCategory collector.DfwCategory) (*AbstractModelSyn, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	for _, groups := range config.GroupsPerVM {
		for _, group := range groups {
			str := group.Expression.String()
			if str != "" {
				fmt.Printf("\tgroup expr %v\n", group.Expression.String())
			}
		}
	}
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, categoryToPolicy, allowOnlyFromCategory, hints)
	abstractModel := &AbstractModelSyn{vms: parser.VMs(), epToGroups: parser.GetConfig().GroupsPerVM,
		allowOnlyFromCategory: allowOnlyFromCategory, policy: []*symbolicPolicy{&allowOnlyPolicy}}
	return abstractModel, createK8sResources(abstractModel, outDir)
}
