package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

func NSXToK8sSynthesis(
	recourses *collector.ResourcesContainerModel,
	hints *symbolicexpr.Hints, synthesizeAdmin, color bool) (*k8sResources, error) {
	abstractModel, err := NSXToPolicy(recourses, hints, synthesizeAdmin, color)
	if err != nil {
		return nil, err
	}
	return createK8sResources(abstractModel), nil
}

func NSXToPolicy(recourses *collector.ResourcesContainerModel,
	hints *symbolicexpr.Hints, synthesizeAdmin, color bool) (*AbstractModelSyn, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	preProcessingCategoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	preProcessingPolicyStr := printPreProcessingSymbolicPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, color)
	logging.Debugf("pre processing symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", preProcessingPolicyStr)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, synthesizeAdmin, hints)
	abstractModel := &AbstractModelSyn{vms: parser.VMs(), epToGroups: parser.GetConfig().GroupsPerVM,
		synthesizeAdmin: synthesizeAdmin, policy: []*symbolicPolicy{&allowOnlyPolicy}, defaultDenyRule: config.DefaultDenyRule()}
	abstractPolicyStr := strAllowOnlyPolicy(&allowOnlyPolicy, color)
	logging.Debugf("allow only symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", abstractPolicyStr)
	return abstractModel, nil
}
