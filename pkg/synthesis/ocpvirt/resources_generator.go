package ocpvirt

import (
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/policy"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/resources"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/topology"
)

type resourcesGenerator struct {
	// generators
	topologyGen *topology.NetworkTopologyGenerator
	policyGen   *policy.PolicyGenerator

	// input objects for generation
	options         *config.SynthesisOptions
	synthModel      *model.AbstractModelSyn
	createDNSPolicy bool

	// resources generated
	resources.Generated

	// additional output values
	NotFullySupported bool
}

func newResourcesGenerator(synthModel *model.AbstractModelSyn, createDNSPolicy bool, options *config.SynthesisOptions) *resourcesGenerator {
	return &resourcesGenerator{
		synthModel:      synthModel,
		createDNSPolicy: createDNSPolicy,
		options:         options,

		topologyGen: topology.NewNetworkTopologyGenerator(synthModel, options),
		policyGen:   policy.NewPolicyGenerator(synthModel, createDNSPolicy),
	}
}

// generate() performs all resources generation - network topology and network policy resources
func (r *resourcesGenerator) generate() {
	// first generate network topology resources
	r.topologyGen.Generate()

	// then generate network policy resources
	r.policyGen.Generate(r.topologyGen.NamespacesInfo)

	// store generated topology resources in resourcesGenerator
	r.CopyTopologyResources(&r.topologyGen.Generated)

	// store generated policy resources in resourcesGenerator
	r.CopyPolicyResources(&r.policyGen.Generated)

	// update NotFullySupported indication
	r.NotFullySupported = r.topologyGen.NotFullySupported || r.policyGen.NotFullySupported

	// summarize generation process
	r.Log()
}
