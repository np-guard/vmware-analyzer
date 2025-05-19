package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// //////////////////////////////////////////////////////////////////////////////////////////
// toLegalK8SString() removes all the k8s illegal characters
// allowed characters are letters, numbers, '-', '.', '_'
// this is a temp fix, still todo:
// 1. two different illegal tags might create the same tag
// 2. fix for pods names should be more restrict (only lower, no '_', ...)
var reg = regexp.MustCompile(`[^-A-Za-z0-9_.]`)

func ToLegalK8SString(s string) string {
	return reg.ReplaceAllString(s, "")
}

//////////////////////////////////////////////////////////////////////////////////////////

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
	logging.Debug2f("%s", cmd.String())
	return true, cmd.Run()
}
