package ocpvirt

import (
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
	logging.Debugf("started synthesis")

	// first stage: convert nsx config to abstract model (includes policy "flattening")
	abstractModel, err := model.NSXConfigToAbstractModel(resources, nsxConfig, options)
	if err != nil {
		return nil, err
	}

	// second stage: generate concrete ocp-virt resources from abstract model
	rg := newResourcesGenerator(abstractModel, options.CreateDNSPolicy, options)
	rg.generate()

	// return generated resources
	return rg, nil
}
