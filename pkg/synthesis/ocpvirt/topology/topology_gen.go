package topology

import (
	core "k8s.io/api/core/v1"

	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

type NetworkTopologyGenerator struct {
	synthModel *model.AbstractModelSyn

	NamespacesInfo    *NamespacesInfo
	NotFullySupported bool

	// generated resources
	Pods       []*core.Pod
	Namespaces []*core.Namespace

	// todo: Add generation of UDNs and VMs resources
}

func NewNetworkTopologyGenerator(synthModel *model.AbstractModelSyn) *NetworkTopologyGenerator {
	return &NetworkTopologyGenerator{
		synthModel:     synthModel,
		NamespacesInfo: NewNamespacesInfo(synthModel.VMs),
	}
}

func (nt *NetworkTopologyGenerator) Generate() {
	nt.NamespacesInfo.InitNamespaces(nt.synthModel)
	nt.Namespaces = nt.NamespacesInfo.CreateNamespaces()
	nt.Pods = nt.createPods()
}

func (nt *NetworkTopologyGenerator) createPods() (res []*core.Pod) {
	for _, vm := range nt.synthModel.VMs {
		nt.NotFullySupported = nt.NotFullySupported || len(nt.synthModel.VMsSegments[vm]) > 1
		pod := &core.Pod{}
		pod.Kind = "Pod"
		pod.APIVersion = "v1"
		pod.Name = utils.ToLegalK8SString(vm.Name())
		pod.Namespace = nt.NamespacesInfo.VMNamespace[vm].Name
		if len(nt.synthModel.EndpointsToGroups[vm]) == 0 {
			continue
		}
		pod.Labels = map[string]string{}

		for _, label := range utils.CollectVMLabels(nt.synthModel, vm) {
			pod.Labels[utils.ToLegalK8SString(label)] = "true"
		}
		res = append(res, pod)
	}
	return res
}
