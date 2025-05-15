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
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/policy_utils"
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

	g.printPoliciesDetails()
}

func logGeneratedResources(kind string, num int) {
	logging.Infof("generated %d %s", num, kind)
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
	logging.Infof("writing generated resources YAMLs to %s", outDir)

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

func (g *Generated) printPoliciesDetails() {
	sections := &common.SectionsOutput{}

	g.addAdminNetpolSectionDetails(sections)
	g.addNetpolSectionDetails(sections)
	g.addPolicyAnnotationsDetails(sections)

	logging.Infof("the generated policy details: %s", sections.GenerateSectionsString())
}

const (
	nameTitle        = "NAME"
	podSelectorTitle = "POD-SELECTOR"
)

func (g *Generated) addNetpolSectionDetails(sections *common.SectionsOutput) {
	// network policies
	section := "Policies details:"
	header := []string{"NAMESPACE", nameTitle, podSelectorTitle}
	lines := [][]string{}

	for _, netpol := range g.NetworkPolicies {
		line := []string{netpol.Namespace, netpol.Name, policy_utils.LabelSelectorString(&netpol.Spec.PodSelector)}
		lines = append(lines, line)
	}
	tableStr := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true})
	sections.AddSection(section, tableStr)
}

func (g *Generated) addAdminNetpolSectionDetails(sections *common.SectionsOutput) {
	// admin network policies
	section := "Admin Policy details"
	header := []string{nameTitle, "PRIORITY", "NAMESPACE-SELECTOR", podSelectorTitle}
	lines := [][]string{}
	for _, netpol := range g.AdminNetworkPolicies {
		nsSelector, podsSelector := policy_utils.AdminPolicySubjectSelectorString(netpol)
		line := []string{netpol.Name, common.IntStr(netpol.Spec.Priority), nsSelector, podsSelector}
		lines = append(lines, line)
	}
	tableStr := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true})
	// todo: don't add this section if empty?
	sections.AddSection(section, tableStr)
}

func (g *Generated) addPolicyAnnotationsDetails(sections *common.SectionsOutput) {
	section := "Policy annotations details"
	header := []string{nameTitle, "DESCRIPTION", "NSX-ID"}
	lines := [][]string{}
	for _, netpol := range g.AdminNetworkPolicies {
		name := policy_utils.NetpolStr(&netpol.TypeMeta, &netpol.ObjectMeta)
		line := []string{name, netpol.Annotations[policy_utils.AnnotationDescription], netpol.Annotations[policy_utils.AnnotationNSXRuleUID]}
		lines = append(lines, line)
	}
	for _, netpol := range g.NetworkPolicies {
		name := policy_utils.NetpolStr(&netpol.TypeMeta, &netpol.ObjectMeta)
		line := []string{name, netpol.Annotations[policy_utils.AnnotationDescription], netpol.Annotations[policy_utils.AnnotationNSXRuleUID]}
		lines = append(lines, line)
	}
	tableStr := common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true})
	sections.AddSection(section, tableStr)
}
