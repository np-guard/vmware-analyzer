package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

type SynthesisOptions struct {
	Hints           *symbolicexpr.Hints
	SynthesizeAdmin bool
	Color           bool
	CreateDnsPolicy bool
}

func NSXToK8sSynthesis(
	recourses *collector.ResourcesContainerModel,
	options *SynthesisOptions,
) (*k8sResources, error) {
	abstractModel, err := NSXToPolicy(recourses, options)
	if err != nil {
		return nil, err
	}
	return createK8sResources(abstractModel,options.CreateDnsPolicy), nil
}

func NSXToPolicy(recourses *collector.ResourcesContainerModel,
	options *SynthesisOptions) (*AbstractModelSyn, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	logging.Debugf("started synthesis")
	preProcessingCategoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	preProcessingPolicyStr := printPreProcessingSymbolicPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, options.Color)
	logging.Debugf("pre processing symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", preProcessingPolicyStr)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, options.SynthesizeAdmin, options.Hints)
	abstractModel := &AbstractModelSyn{vms: parser.VMs(), epToGroups: parser.GetConfig().GroupsPerVM,
		synthesizeAdmin: options.SynthesizeAdmin, policy: []*symbolicPolicy{&allowOnlyPolicy}, defaultDenyRule: config.DefaultDenyRule()}
	abstractPolicyStr := strAllowOnlyPolicy(&allowOnlyPolicy, options.Color)
	logging.Debugf("allow only symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", abstractPolicyStr)
	return abstractModel, nil
}
