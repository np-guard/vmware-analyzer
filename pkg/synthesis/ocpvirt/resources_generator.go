package ocpvirt

import (
	"os"
	"path"
	"path/filepath"

	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/policy"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

type resourcesGenerator struct {
	// generators
	topologyGen *topology.NetworkTopologyGenerator
	policyGen   *policy.PolicyGenerator

	// input objects for generation
	synthModel      *model.AbstractModelSyn
	createDNSPolicy bool

	// resources generated
	Pods                 []*core.Pod
	Namespaces           []*core.Namespace
	NetworkPolicies      []*networking.NetworkPolicy
	AdminNetworkPolicies []*admin.AdminNetworkPolicy

	// additional output values
	NotFullySupported bool
}

func newResourcesGenerator(synthModel *model.AbstractModelSyn, createDNSPolicy bool) *resourcesGenerator {
	return &resourcesGenerator{
		synthModel:      synthModel,
		createDNSPolicy: createDNSPolicy,

		topologyGen: topology.NewNetworkTopologyGenerator(synthModel),
		policyGen:   policy.NewPolicyGenerator(synthModel, createDNSPolicy),
	}
}

// generate performs all resources generation - network topology and policy resources
func (r *resourcesGenerator) generate() {
	r.topologyGen.Generate()
	r.policyGen.Generate(r.topologyGen.NamespacesInfo)

	r.Pods = r.topologyGen.Pods
	r.Namespaces = r.topologyGen.Namespaces
	r.NetworkPolicies = r.policyGen.NetworkPolicies
	r.AdminNetworkPolicies = r.policyGen.AdminNetworkPolicies

	r.NotFullySupported = r.topologyGen.NotFullySupported || r.policyGen.NotFullySupported

	// summarize generation process
	logging.Debugf("%d k8s network policies,%d admin network policies, and %d pods were generated",
		len(r.policyGen.NetworkPolicies),
		len(r.policyGen.AdminNetworkPolicies),
		len(r.topologyGen.Pods))
}

func (r *resourcesGenerator) CreateDir(outDir string) error {
	outDir = filepath.Join(outDir, utils.K8sResourcesDir)
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	if len(r.NetworkPolicies) > 0 {
		policiesFileName := path.Join(outDir, "policies.yaml")
		if err := common.WriteYamlUsingJSON(r.NetworkPolicies, policiesFileName); err != nil {
			return err
		}
	}
	if len(r.AdminNetworkPolicies) > 0 {
		adminPoliciesFileName := path.Join(outDir, "adminPolicies.yaml")
		if err := common.WriteYamlUsingJSON(r.AdminNetworkPolicies, adminPoliciesFileName); err != nil {
			return err
		}
	}
	if len(r.Namespaces) > 0 {
		namespacesFileName := path.Join(outDir, "namespaces.yaml")
		if err := common.WriteYamlUsingJSON(r.Namespaces, namespacesFileName); err != nil {
			return err
		}
	}
	podsFileName := path.Join(outDir, "pods.yaml")
	if err := common.WriteYamlUsingJSON(r.Pods, podsFileName); err != nil {
		return err
	}
	return nil
}
