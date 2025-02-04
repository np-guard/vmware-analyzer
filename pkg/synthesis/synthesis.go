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
	fmt.Println("VMs to Groups:\n~~~~~~~~~~~")
	for vm, groups := range config.GroupsPerVM {
		fmt.Println("vm:", vm.Name())
		for _, group := range groups {
			fmt.Println("\t", group.Name())
		}
	}
	fmt.Println("effective rules\n~~~~~~~~~~~~~~~~~~~~~~~~~\n", config.Fw.AllEffectiveRules())
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, categoryToPolicy, allowOnlyFromCategory, hints)
	abstractModel := &AbstractModelSyn{vms: parser.VMs(), epToGroups: parser.GetConfig().GroupsPerVM,
		allowOnlyFromCategory: allowOnlyFromCategory, policy: []*symbolicPolicy{&allowOnlyPolicy}}
	fmt.Println("allow only\n~~~~~~~~~~~~\n", strAllowOnlyPolicy(abstractModel.policy[0]))
	return abstractModel, createK8sResources(abstractModel, outDir)
}
