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
	logging.Debugf("started synthesis")
	preProcessingCategoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	preProcessingPolicyStr := printPreProcessingSymbolicPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, color)
	logging.Debugf("pre processing symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", preProcessingPolicyStr)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, synthesizeAdmin, hints)
	forK8sPolicy := policyToPolicyForK8s(&allowOnlyPolicy)
	abstractModel := &AbstractModelSyn{vms: parser.VMs(), epToGroups: parser.GetConfig().GroupsPerVM,
		synthesizeAdmin: synthesizeAdmin, policy: []*symbolicPolicy{&allowOnlyPolicy},
		policyForK8sSynthesis: forK8sPolicy, defaultDenyRule: config.DefaultDenyRule()}
	abstractPolicyStr := strAllowOnlyPolicy(&allowOnlyPolicy, color)
	logging.Debugf("allow only symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", abstractPolicyStr)
	return abstractModel, nil
}

func policyToPolicyForK8s(policy *symbolicPolicy) *symbolicPolicyK8sSynthesis {
	_ = policy
	idToPolicyK8sSynthesis := map[string]*symbolicRuleByOrig{}
	res := make(symbolicPolicyK8sSynthesis, len(idToPolicyK8sSynthesis))
	i := 0
	for _, val := range idToPolicyK8sSynthesis {
		res[i] = val
		i++
	}
	return &res

}
