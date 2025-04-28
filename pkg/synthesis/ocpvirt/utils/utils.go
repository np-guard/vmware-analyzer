package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

// //////////////////////////////////////////////////////////////////////////////////////////
// toLegalK8SString() replaces all the k8s illegal characters with "-NLC"
// allowed characters are letters, numbers, '-', '.', '_'
// this is a temp fix, still todo:
// 1. two different illegal tags might create the same tag
// 2. fix for pods names should be more restrict (only lower, no '_', ...)
var reg = regexp.MustCompile(`[^-A-Za-z0-9_.]`)

func ToLegalK8SString(s string) string {
	return reg.ReplaceAllString(s, "-NLC")
}

// todo - move these two methods to the right place.
func CollectLabelsVMs(synthModel *model.AbstractModelSyn) map[string][]topology.Endpoint {
	labelsVMs := map[string][]topology.Endpoint{}
	for _, vm := range synthModel.VMs {
		labels := CollectVMLabels(synthModel, vm)
		for _, label := range labels {
			labelsVMs[label] = append(labelsVMs[label], vm)
		}
	}
	return labelsVMs
}
func CollectVMLabels(synthModel *model.AbstractModelSyn, vm topology.Endpoint) []string {
	labels := []string{}

	for _, tag := range vm.Tags() {
		label, _ := symbolicexpr.NewTagTerm(tag, false).AsSelector()
		labels = append(labels, label)
	}
	for _, group := range synthModel.EndpointsToGroups[vm] {
		label, _ := symbolicexpr.NewGroupAtomicTerm(group, false).AsSelector()
		labels = append(labels, label)
	}
	for _, segment := range synthModel.VMsSegments[vm] {
		label, _ := symbolicexpr.NewSegmentTerm(segment, false).AsSelector()
		labels = append(labels, label)
	}
	for _, ruleIPBlock := range synthModel.RuleBlockPerEndpoint[vm] {
		if !ruleIPBlock.IsAll() {
			label, _ := symbolicexpr.NewInternalIPTerm(ruleIPBlock, false).AsSelector()
			labels = append(labels, label)
		}
	}
	return labels
}

const K8sResourcesDir = "k8s_resources"

func K8sAnalyzer(k8sDir, outfile, format string) (bool, error) {
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
