package topology

import (
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirt "kubevirt.io/api/core/v1"

	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

const migratedLabelValue = "true"

func (nt *NetworkTopologyGenerator) createPods() (res []*core.Pod) {
	for _, vm := range nt.synthModel.VMs {
		if len(nt.synthModel.EndpointsToGroups[vm]) == 0 {
			// skipping vms without groups
			continue
		}

		nt.NotFullySupported = nt.NotFullySupported || len(nt.synthModel.VMsSegments[vm]) > 1
		pod := &core.Pod{}
		pod.Kind = "Pod"
		pod.APIVersion = apiVersion
		pod.Name = utils.ToLegalK8SString(vm.Name())
		pod.Namespace = nt.NamespacesInfo.vmNamespace[vm].Name

		pod.Labels = map[string]string{}

		for _, label := range nt.synthModel.VMToLablesMap[vm.Name()] {
			pod.Labels[utils.ToLegalK8SString(label)] = migratedLabelValue
		}
		res = append(res, pod)
	}
	return res
}
func (nt *NetworkTopologyGenerator) createVMs() (res []*kubevirt.VirtualMachine) {
	// create vms resources with required labels migration for micro-segmentation to work
	for _, vm := range nt.synthModel.VMs {
		if len(nt.synthModel.EndpointsToGroups[vm]) == 0 {
			// skipping vms without groups
			continue
		}
		ocpVM := &kubevirt.VirtualMachine{}
		ocpVM.Kind = "VirtualMachine"
		ocpVM.APIVersion = "kubevirt.io/v1"
		ocpVM.Name = utils.ToLegalK8SString(vm.Name())
		ocpVM.Namespace = nt.NamespacesInfo.vmNamespace[vm].Name

		// add required labels migration for micro-segmentation at the VMI spec template,
		// and not at the VM labels (so that virt-launcher-pod gets the right labels)
		ocpVM.Spec = kubevirt.VirtualMachineSpec{
			Template: &kubevirt.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{},
				},
			},
		}

		for _, label := range nt.synthModel.VMToLablesMap[vm.Name()] {
			ocpVM.Spec.Template.ObjectMeta.Labels[utils.ToLegalK8SString(label)] = migratedLabelValue
		}
		res = append(res, ocpVM)
	}
	return res
}
