package resources

import (
	"errors"
	"os"
	"path"
	"path/filepath"

	udnv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	kubevirt "kubevirt.io/api/core/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// contains all generated resources
type Generated struct {
	Pods                 []*core.Pod
	VMs                  []*kubevirt.VirtualMachine
	Namespaces           []*core.Namespace
	UDNs                 []*udnv1.UserDefinedNetwork
	NetworkPolicies      []*networking.NetworkPolicy
	AdminNetworkPolicies []*admin.AdminNetworkPolicy
}

func (g *Generated) Log() {
	logGeneratedResources("network policies", len(g.NetworkPolicies))
	logGeneratedResources("admin network policies", len(g.AdminNetworkPolicies))
	logGeneratedResources("namespaces", len(g.Namespaces))
	logGeneratedResources("udns", len(g.UDNs))
	logGeneratedResources("pods", len(g.Pods))
	logGeneratedResources("vms", len(g.VMs))
}

func logGeneratedResources(kind string, num int) {
	logging.Debugf("generated %d %s", num, kind)
}

func (g *Generated) CopyPolicyResources(g1 *Generated) {
	g.NetworkPolicies = g1.NetworkPolicies
	g.AdminNetworkPolicies = g1.AdminNetworkPolicies
}

func (g *Generated) CopyTopologyResources(g1 *Generated) {
	g.Pods = g1.Pods
	g.VMs = g1.VMs
	g.Namespaces = g1.Namespaces
	g.UDNs = g1.UDNs
}

const K8sResourcesDir = "k8s_resources" // todo: rename to ocp-virt-resources

// WriteResourcesToDir writes YAML files in K8sResourcesDir with generated OCP-Virt resources
func (g *Generated) WriteResourcesToDir(outDir string) error {
	outDir = filepath.Join(outDir, K8sResourcesDir)
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}

	err1 := yamlWriter(g.NetworkPolicies, "policies.yaml", outDir)
	err2 := yamlWriter(g.AdminNetworkPolicies, "adminPolicies.yaml", outDir)
	err3 := yamlWriter(g.Namespaces, "namespaces.yaml", outDir)
	err4 := yamlWriter(g.UDNs, "udns.yaml", outDir)
	err5 := yamlWriter(g.VMs, "vms.yaml", outDir)
	err6 := yamlWriter(g.Pods, "pods.yaml", outDir)

	return errors.Join(err1, err2, err3, err4, err5, err6)
}

func yamlWriter[A any](content []A, file, outDir string) error {
	if len(content) > 0 {
		fileName := path.Join(outDir, file)
		if err := common.WriteYamlUsingJSON(content, fileName); err != nil {
			return err
		}
	}
	return nil
}
