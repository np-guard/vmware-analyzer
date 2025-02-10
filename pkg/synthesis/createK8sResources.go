package synthesis

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"

	core "k8s.io/api/core/v1"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

const k8sResourcesDir = "k8s_resources"

func createK8sResources(model *AbstractModelSyn, outDir string) error {
	outDir = filepath.Join(outDir, k8sResourcesDir)
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	k8sPolicies := &k8sPolicies{}
	policies, adminPolicies := k8sPolicies.toNetworkPolicies(model)
	if len(policies) > 0 {
		policiesFileName := path.Join(outDir, "policies.yaml")
		if err := common.WriteYamlUsingJSON(policies, policiesFileName); err != nil {
			return err
		}
	}
	if len(adminPolicies) > 0 {
		adminPoliciesFileName := path.Join(outDir, "adminPolicies.yaml")
		if err := common.WriteYamlUsingJSON(adminPolicies, adminPoliciesFileName); err != nil {
			return err
		}
	}
	pods := toPods(model)
	podsFileName := path.Join(outDir, "pods.yaml")
	if err := common.WriteYamlUsingJSON(pods, podsFileName); err != nil {
		return err
	}
	logging.Debugf("%d k8s network policies, and %d admin network policies were generated at %s",
		len(policies), len(adminPolicies), outDir)
	return nil
}

// ///////////////////////////////////////////////////////////////////////////////
func toPods(model *AbstractModelSyn) []*core.Pod {
	pods := []*core.Pod{}
	for _, vm := range model.vms {
		pod := &core.Pod{}
		pod.TypeMeta.Kind = "Pod"
		pod.TypeMeta.APIVersion = "v1"
		pod.ObjectMeta.Name = vm.Name()
		if len(model.epToGroups[vm]) == 0 {
			continue
		}
		pod.ObjectMeta.Labels = map[string]string{}
		const theTrue = "true"
		for _, group := range model.epToGroups[vm] {
			label, _ := symbolicexpr.NewGroupAtomicTerm(group, false).AsSelector()
			pod.ObjectMeta.Labels[label] = theTrue
		}
		for _, tag := range vm.Tags() {
			label, _ := symbolicexpr.NewTagTerm(tag, false).AsSelector()
			pod.ObjectMeta.Labels[label] = theTrue
		}
		pods = append(pods, pod)
	}
	return pods
}

///////////////////////////////////////////////////////////////////////////

func k8sAnalyzer(k8sDir, outfile, format string) error {
	analyzerExec := "k8snetpolicy"

	// looking for the analyzerExec in:
	// 1. the location of the exec that currently running (the vmware-analyzer)
	// 2. the bin/ directory of this project
	// 3. in $PATH environment variable
	runningExec, err := os.Executable()
	if err != nil {
		return err
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
		return nil
	}
	cmd := exec.Command(analyzerExecPath, "list", "--dirpath", k8sDir, "--file", outfile, "--output", format)
	return cmd.Run()
}
