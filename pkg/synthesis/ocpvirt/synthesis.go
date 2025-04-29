package ocpvirt

import (
	"maps"
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
)

// this file contains the main API to ocpvirt synthesis from NSX configuration

func NSXToK8sSynthesis(
	resources *collector.ResourcesContainerModel,
	nsxConfig *configuration.Config,
	options *config.SynthesisOptions,
) (*resourcesGenerator, error) {
	// first stage: convert nsx config to abstract model
	abstractModel, err := NsxToPolicy(resources, nsxConfig, options)
	if err != nil {
		return nil, err
	}
	// second stage: generate concrete ocp-virt resources from abstract model
	rg := NewResourcesGenerator(abstractModel, options.CreateDNSPolicy)
	rg.Generate()

	// return generated resources
	return rg, nil
}

func NsxToPolicy(resources *collector.ResourcesContainerModel,
	nsxConfig *configuration.Config,
	options *config.SynthesisOptions) (*model.AbstractModelSyn, error) {
	if nsxConfig == nil {
		var err error
		nsxConfig, err = configuration.ConfigFromResourcesContainer(resources, options.OutputOption())
		if err != nil {
			return nil, err
		}
	}

	logging.Debugf("started synthesis")
	preProcessingCategoryToPolicy := model.PreProcessing(nsxConfig.FW.CategoriesSpecs)
	preProcessingPolicyStr := model.PrintPreProcessingSymbolicPolicy(nsxConfig.FW.CategoriesSpecs, preProcessingCategoryToPolicy,
		options.Color)
	logging.Debugf("pre processing symbolic rules\n=============================\n%v", preProcessingPolicyStr)
	allowOnlyPolicy := model.ComputeAllowOnlyRulesForPolicy(
		nsxConfig.FW.CategoriesSpecs, preProcessingCategoryToPolicy,
		options.SynthesizeAdmin, options.Hints)
	allowOnlyPolicyWithOptimization := model.OptimizeSymbolicPolicy(&allowOnlyPolicy, options)
	// todo: move this object creation to package model
	abstractModel := &model.AbstractModelSyn{
		Config:               nsxConfig,
		VMs:                  nsxConfig.VMs,
		Segments:             nsxConfig.Topology.Segments,
		AllGroups:            nsxConfig.Groups,
		EndpointsToGroups:    nsxConfig.GroupsPerVM,
		AllRuleIPBlocks:      slices.Collect(maps.Values(nsxConfig.Topology.AllRuleIPBlocks)),
		RuleBlockPerEndpoint: nsxConfig.Topology.RuleBlockPerEP,
		VMsSegments:          nsxConfig.Topology.VmSegments,
		ExternalIP:           nsxConfig.Topology.AllExternalIPBlock,
		SynthesizeAdmin:      options.SynthesizeAdmin,
		Policy:               []*model.SymbolicPolicy{allowOnlyPolicyWithOptimization},
		DefaultDenyRule:      nsxConfig.DefaultDenyRule()}
	abstractModelStr := model.StrAbstractModel(abstractModel, options)
	logging.Debugf("abstract model\n==============\n%v", abstractModelStr)
	return abstractModel, nil
}
