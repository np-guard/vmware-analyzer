package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

func NSXToK8sSynthesis(
	recourses *collector.ResourcesContainerModel, outDir string, hints *symbolicexpr.Hints,
	allowOnlyFromCategory collector.DfwCategory, color bool) error {
	abstractModel, err := NSXToPolicy(recourses, hints, allowOnlyFromCategory, color)
	if err != nil {
		return err
	}
	return createK8sResources(abstractModel, outDir)
}

func NSXToPolicy(recourses *collector.ResourcesContainerModel,
	hints *symbolicexpr.Hints, allowOnlyFromCategory collector.DfwCategory, color bool) (*AbstractModelSyn, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	preProcessingCategoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	preProcessingPolicyStr := printPreProcessingSymbolicPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, color)
	logging.Debugf("pre processing symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", preProcessingPolicyStr)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, allowOnlyFromCategory, hints)
	abstractModel := &AbstractModelSyn{vms: parser.VMs(), epToGroups: parser.GetConfig().GroupsPerVM,
		allowOnlyFromCategory: allowOnlyFromCategory, policy: []*symbolicPolicy{&allowOnlyPolicy}}
	abstractPolicyStr := strAllowOnlyPolicy(&allowOnlyPolicy, color)
	logging.Debugf("allow only symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", abstractPolicyStr)
	return abstractModel, nil
}
