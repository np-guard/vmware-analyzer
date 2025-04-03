package synthesis

import (
	"maps"
	"slices"

	"github.com/np-guard/vmware-analyzer/internal/common"
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
	FilterVMs       []string
}

func (options SynthesisOptions) outputOption() common.OutputParameters {
	return common.OutputParameters{Color: options.Color, VMs: options.FilterVMs}
}

func NSXToK8sSynthesis(
	resources *collector.ResourcesContainerModel,
	config *configuration.Config,
	options *SynthesisOptions,
) (*k8sResources, error) {
	abstractModel, err := NSXToPolicy(resources, config, options)
	if err != nil {
		return nil, err
	}
	return createK8sResources(abstractModel, options.CreateDNSPolicy), nil
}

func NSXToPolicy(resources *collector.ResourcesContainerModel,
	config *configuration.Config,
	options *SynthesisOptions) (*AbstractModelSyn, error) {
	if config == nil {
		var err error
		config, err = configuration.ConfigFromResourcesContainer(resources, options.outputOption())
		if err != nil {
			return nil, err
		}
	}

	logging.Debugf("started synthesis")
	preProcessingCategoryToPolicy := preProcessing(config.FW.CategoriesSpecs)
	preProcessingPolicyStr := printPreProcessingSymbolicPolicy(config.FW.CategoriesSpecs, preProcessingCategoryToPolicy,
		options.Color)
	logging.Debugf("pre processing symbolic rules\n=============================\n%v", preProcessingPolicyStr)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(
		config.FW.CategoriesSpecs, preProcessingCategoryToPolicy,
		options.SynthesizeAdmin, options.Hints)
	allowOnlyPolicyWithOptimization := optimizeSymbolicPolicy(&allowOnlyPolicy, options)
	abstractModel := &AbstractModelSyn{
		vms:             config.VMs,
		segments:        config.Topology.Segments,
		allGroups:       config.Groups,
		epToGroups:      config.GroupsPerVM,
		allRuleIPBlocks: slices.Collect(maps.Values(config.Topology.AllRuleIPBlocks)),
		ruleBlockPerEP:  config.Topology.RuleBlockPerEP,
		vmSegments:      config.Topology.VmSegments,
		synthesizeAdmin: options.SynthesizeAdmin,
		policy:          []*symbolicPolicy{allowOnlyPolicyWithOptimization},
		defaultDenyRule: config.DefaultDenyRule()}
	abstractModelStr := strAbstractModel(abstractModel, options)
	logging.Debugf("abstract model\n==============\n%v", abstractModelStr)
	return abstractModel, nil
}
