package synthesis

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"

	core "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

const k8sResourcesDir = "k8s_resources"
const apiVersion = "v1"

type k8sResources struct {
	k8sPolicies
	pods       []*core.Pod
	namespaces []*core.Namespace
}

func (resources *k8sResources) K8sPolicies() []*v1.NetworkPolicy {
	return resources.networkPolicies
}

func (resources *k8sResources) K8sAdminPolicies() []*v1alpha1.AdminNetworkPolicy {
	return resources.adminNetworkPolicies
}

func createK8sResources(model *AbstractModelSyn, createDNSPolicy bool) *k8sResources {
	k8sResources := &k8sResources{k8sPolicies: k8sPolicies{externalIP: model.ExternalIP}}
	k8sResources.namespacesInfo = newNamespacesInfo(model.vms)
	k8sResources.namespacesInfo.initNamespaces(model)
	k8sResources.createPolicies(model, createDNSPolicy)
	k8sResources.namespaces = k8sResources.namespacesInfo.createResources()
	k8sResources.createPods(model)
	logging.Debugf("%d k8s network policies,%d admin network policies, and %d pods were generated",
		len(k8sResources.networkPolicies), len(k8sResources.adminNetworkPolicies), len(k8sResources.pods))
	return k8sResources
}

func (resources *k8sResources) CreateDir(outDir string) error {
	outDir = filepath.Join(outDir, k8sResourcesDir)
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	if len(resources.networkPolicies) > 0 {
		policiesFileName := path.Join(outDir, "policies.yaml")
		if err := common.WriteYamlUsingJSON(resources.networkPolicies, policiesFileName); err != nil {
			return err
		}
	}
	if len(resources.adminNetworkPolicies) > 0 {
		adminPoliciesFileName := path.Join(outDir, "adminPolicies.yaml")
		if err := common.WriteYamlUsingJSON(resources.adminNetworkPolicies, adminPoliciesFileName); err != nil {
			return err
		}
	}
	if len(resources.namespaces) > 0 {
		namespacesFileName := path.Join(outDir, "namespaces.yaml")
		if err := common.WriteYamlUsingJSON(resources.namespaces, namespacesFileName); err != nil {
			return err
		}
	}
	podsFileName := path.Join(outDir, "pods.yaml")
	if err := common.WriteYamlUsingJSON(resources.pods, podsFileName); err != nil {
		return err
	}
	return nil
}

// ///////////////////////////////////////////////////////////////////////////////
func (resources *k8sResources) createPods(model *AbstractModelSyn) {
	for _, vm := range model.vms {
		resources.NotFullySupported = resources.NotFullySupported || len(model.vmSegments[vm]) > 1
		pod := &core.Pod{}
		pod.Kind = "Pod"
		pod.APIVersion = apiVersion
		pod.Name = toLegalK8SString(vm.Name())
		pod.Namespace = resources.namespacesInfo.vmNamespace[vm].name
		if len(model.epToGroups[vm]) == 0 {
			continue
		}
		pod.Labels = map[string]string{}

		for _, label := range collectVMLabels(model, vm) {
			pod.Labels[toLegalK8SString(label)] = "true"
		}
		resources.pods = append(resources.pods, pod)
	}
}

///////////////////////////////////////////////////////////////////////////

func k8sAnalyzer(k8sDir, outfile, format string) (bool, error) {
	analyzerExec := "k8snetpolicy"

	// looking for the analyzerExec in:
	// 1. the location of the exec that currently running (the vmware-analyzer)
	// 2. the bin/ directory of this project
	// 3. in $PATH environment variable
	runningExec, err := os.Executable()
	if err != nil {
		return false, err
	}
	runningExecDir := filepath.Dir(runningExec)
	potentialAnalyzerExecPaths := []string{
		filepath.Join(runningExecDir, analyzerExec),
		filepath.Join(projectpath.Root, "bin", analyzerExec),
	}

	atPath, err := exec.LookPath(analyzerExec)
	if err == nil {
		potentialAnalyzerExecPaths = append(potentialAnalyzerExecPaths, atPath)
	}

	var analyzerExecPath string
	for _, path := range potentialAnalyzerExecPaths {
		if common.FileExist(path) {
			analyzerExecPath = path
			break
		}
	}
	if analyzerExecPath == "" {
		return false, nil
	}
	cmd := exec.Command(analyzerExecPath, "list", "--dirpath", k8sDir, "--file", outfile, "--output", format)
	logging.Debug(cmd.String())
	return true, cmd.Run()
}
