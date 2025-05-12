package topology

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/resources"
)

// NetworkTopologyGenerator implements the functionality to generate network topology resources
// from the input abstract model and nsx config
type NetworkTopologyGenerator struct {
	// input abstract model
	synthModel *model.AbstractModelSyn
	options    *config.SynthesisOptions

	// objects for generation process
	NamespacesInfo *NamespacesInfo
	// output indicators
	NotFullySupported bool

	// generated resources
	resources.Generated
}

func NewNetworkTopologyGenerator(synthModel *model.AbstractModelSyn, options *config.SynthesisOptions) *NetworkTopologyGenerator {
	return &NetworkTopologyGenerator{
		synthModel:     synthModel,
		options:        options,
		NamespacesInfo: newNamespacesInfo(synthModel),
	}
}

func (nt *NetworkTopologyGenerator) Generate() {
	// udn-based micro-segmentation
	// namespace generation
	nt.Namespaces = nt.NamespacesInfo.createNamespaces()
	// udn generation
	if nt.options.SegmentsMapping == common.SegmentsToUDNs {
		nt.UDNs = nt.NamespacesInfo.createUDNs()
	}

	// endpoints generation
	switch nt.options.EndpointsMapping {
	case common.EndpointsVMs:
		nt.VMs = nt.createVMs()
	case common.EndpointsPods:
		nt.Pods = nt.createPods()
	case common.EndpointsBoth:
		nt.VMs = nt.createVMs()
		nt.Pods = nt.createPods()
	}
}
