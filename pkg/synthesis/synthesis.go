package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
)

type SynthesisOptions struct {
	Hints           *symbolicexpr.Hints
	SynthesizeAdmin bool
	Color           bool
	CreateDNSPolicy bool
}

func NSXToK8sSynthesis(
	resources *collector.ResourcesContainerModel,
	config configuration.ParsedNSXConfig,
	options *SynthesisOptions,
) (*k8sResources, error) {
	abstractModel, err := NSXToPolicy(resources, config, options)
	if err != nil {
		return nil, err
	}
	return createK8sResources(abstractModel, options.CreateDNSPolicy), nil
}

func NSXToPolicy(resources *collector.ResourcesContainerModel,
	config configuration.ParsedNSXConfig,
	options *SynthesisOptions) (*AbstractModelSyn, error) {
	if config == nil {
		var err error
		config, err = configuration.ConfigFromResourcesContainer(resources, options.Color)
		if err != nil {
			return nil, err
		}
	}

	logging.Debugf("started synthesis")
	preProcessingCategoryToPolicy := preProcessing(config.DFW().CategoriesSpecs)
	preProcessingPolicyStr := printPreProcessingSymbolicPolicy(config.DFW().CategoriesSpecs, preProcessingCategoryToPolicy,
		options.Color)
	logging.Debugf("pre processing symbolic rules\n=============================\n%v", preProcessingPolicyStr)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(
		config.DFW().CategoriesSpecs, preProcessingCategoryToPolicy,
		options.SynthesizeAdmin, options.Hints)
	allowOnlyPolicyWithOptimization := optimizeSymbolicPolicy(&allowOnlyPolicy, options)
	abstractModel := &AbstractModelSyn{vms: config.VMs(), allGroups: config.GetGroups(), epToGroups: config.VMToGroupsMap(),
		synthesizeAdmin: options.SynthesizeAdmin, policy: []*symbolicPolicy{allowOnlyPolicyWithOptimization},
		defaultDenyRule: config.DefaultDenyRule()}
	abstractModelStr := strAbstractModel(abstractModel, options)
	logging.Debugf("abstract model\n==============\n%v", abstractModelStr)
	return abstractModel, nil
}
