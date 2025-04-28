package ocpvirt

import (
	"os"
	"path"
	"path/filepath"

	core "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/policy"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

type k8sResources struct {
	policy.K8sPolicies
	Pods       []*core.Pod
	Namespaces []*core.Namespace
}

func (resources *k8sResources) K8sPoliciesList() []*v1.NetworkPolicy {
	return resources.NetworkPolicies
}

func (resources *k8sResources) K8sAdminPolicies() []*v1alpha1.AdminNetworkPolicy {
	return resources.AdminNetworkPolicies
}

func createK8sResources(synthModel *model.AbstractModelSyn, createDNSPolicy bool) *k8sResources {
	k8sResources := &k8sResources{}
	k8sResources.K8sPolicies = policy.K8sPolicies{ExternalIP: synthModel.ExternalIP}
	k8sResources.NamespacesInfo = topology.NewNamespacesInfo(synthModel.VMs)
	k8sResources.NamespacesInfo.InitNamespaces(synthModel)
	k8sResources.CreatePolicies(synthModel, createDNSPolicy)
	k8sResources.Namespaces = k8sResources.NamespacesInfo.CreateResources()
	k8sResources.createPods(synthModel)
	logging.Debugf("%d k8s network policies,%d admin network policies, and %d pods were generated",
		len(k8sResources.NetworkPolicies), len(k8sResources.AdminNetworkPolicies), len(k8sResources.Pods))
	return k8sResources
}

func (resources *k8sResources) CreateDir(outDir string) error {
	outDir = filepath.Join(outDir, utils.K8sResourcesDir)
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	if len(resources.NetworkPolicies) > 0 {
		policiesFileName := path.Join(outDir, "policies.yaml")
		if err := common.WriteYamlUsingJSON(resources.NetworkPolicies, policiesFileName); err != nil {
			return err
		}
	}
	if len(resources.AdminNetworkPolicies) > 0 {
		adminPoliciesFileName := path.Join(outDir, "adminPolicies.yaml")
		if err := common.WriteYamlUsingJSON(resources.AdminNetworkPolicies, adminPoliciesFileName); err != nil {
			return err
		}
	}
	if len(resources.Namespaces) > 0 {
		namespacesFileName := path.Join(outDir, "namespaces.yaml")
		if err := common.WriteYamlUsingJSON(resources.Namespaces, namespacesFileName); err != nil {
			return err
		}
	}
	podsFileName := path.Join(outDir, "pods.yaml")
	if err := common.WriteYamlUsingJSON(resources.Pods, podsFileName); err != nil {
		return err
	}
	return nil
}

// ///////////////////////////////////////////////////////////////////////////////
func (resources *k8sResources) createPods(synthModel *model.AbstractModelSyn) {
	for _, vm := range synthModel.VMs {
		resources.NotFullySupported = resources.NotFullySupported || len(synthModel.VMsSegments[vm]) > 1
		pod := &core.Pod{}
		pod.Kind = "Pod"
		pod.APIVersion = "v1"
		pod.Name = utils.ToLegalK8SString(vm.Name())
		pod.Namespace = resources.NamespacesInfo.VMNamespace[vm].Name
		if len(synthModel.EndpointsToGroups[vm]) == 0 {
			continue
		}
		pod.Labels = map[string]string{}

		for _, label := range utils.CollectVMLabels(synthModel, vm) {
			pod.Labels[utils.ToLegalK8SString(label)] = "true"
		}
		resources.Pods = append(resources.Pods, pod)
	}
}

///////////////////////////////////////////////////////////////////////////
