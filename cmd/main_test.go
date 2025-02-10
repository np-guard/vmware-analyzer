/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

var (
	stdoutFile *os.File
	testOutR   *os.File
	testOutW   *os.File
)

// redirect command's execute stdout to a pipe
func preTestRun() {
	stdoutFile = os.Stdout
	testOutR, testOutW, _ = os.Pipe()
	os.Stdout = testOutW
}

// finalize test's command execute and get its output
func postTestRun() string {
	testOutW.Close()
	out, _ := io.ReadAll(testOutR)
	os.Stdout = stdoutFile
	return string(out)
}

// build a new command with args list and execute it, returns the actual output from stdout and the execute err if exists
func buildAndExecuteCommand(args []string) (string, error) {
	preTestRun()
	err := _main(args)
	actualOut := postTestRun()
	return actualOut, err
}

type cliTest struct {
	name                    string
	args                    string   // cli args for this test
	possibleErr             string   // possibleErr to consider depending on env constraints
	expectedOutputSubstring string   // output of successful run
	expectedOutFile         []string // generated output files of successful run
	expectedErr             []string // expectedErr if assigned, should be returned (at least one of the given options)
}

const (
	noDotExecErr    = "exec: \"dot\": executable file not found"
	resourceFileNotFoundErr = "open examples/input/resources.json:"
)

var staticTests = []*cliTest{
	{
		name:        "unsupported_format_check",
		args:        "-r ../pkg/collector/data/json/Example1.json -v -o svg -o ex1.svg ",
		expectedErr: []string{"invalid argument"},
	},
	{
		// version
		name:                    "version",
		args:                    "--version",
		expectedOutputSubstring: "nsxanalyzer version",
	},
	{
		// help
		name:                    "help",
		args:                    "-h",
		expectedOutputSubstring: "Usage:",
	},

	{
		// invalid nsx connections
		name: "invalid_nsx_conn_1",
		args: "--host https://1.1.1.1 --username username --password password",
		expectedErr: []string{"remote error: tls: handshake failure",
			"invalid character" /*indicates that the server did not return a valid JSON response*/},
	},
	{
		// invalid nsx connections
		name:        "invalid_nsx_conn_2",
		args:        "--host 123 --username username --password password",
		expectedErr: []string{"unsupported protocol scheme"},
	},
	{
		// analysis from nsx resources input file
		name:            "analyze-only",
		args:            "--resource-input-file ../pkg/collector/data/json/Example1.json --filename examples/output/analysis-only.txt",
		expectedOutFile: []string{"examples/output/analysis-only.txt"},
	},
	{
		name:            "analyze-only-resources-shorthand-flag",
		args:            "-r ../pkg/collector/data/json/Example1.json --filename examples/output/analysis-only-new.txt",
		expectedOutFile: []string{"examples/output/analysis-only-new.txt"},
	},
	{
		name: "analyze-topology-dot",
		args: "--resource-input-file ../pkg/collector/data/json/Example1.json --topology-dump-file" +
			" examples/output/topology.dot --filename examples/output/analysis.dot -o dot",
		expectedOutFile: []string{"examples/output/topology.dot", "examples/output/analysis.dot"},
	},
	{
		name: "analyze-topology-json",
		args: "--resource-input-file ../pkg/collector/data/json/Example1.json --topology-dump-file" +
			" examples/output/topology.json --filename examples/output/analysis.json -o json",
		expectedOutFile: []string{"examples/output/topology.json", "examples/output/analysis.json"},
	},
	{
		name: "analyze-topology-text",
		args: "--resource-input-file ../pkg/collector/data/json/Example1.json --topology-dump-file" +
			" examples/output/topology.txt --filename examples/output/analysis.txt -o txt",
		expectedOutFile: []string{"examples/output/topology.txt", "examples/output/analysis.txt"},
	},
	{
		name: "synthesize-only",
		args: "--resource-input-file ../pkg/collector/data/json/Example1.json" +
			" --synthesis-dump-dir examples/output/synthesis --disjoint-hint backend,frontend --disjoint-hint frontend,backend",
		expectedOutFile: []string{"examples/output/synthesis/k8s_resources/policies.yaml"},
	},
	{
		name: "anonymize-only",
		args: "--resource-input-file examples/input/resources.json --resource-dump-file examples/output/resources_anon_only.json" +
			" --skip-analysis --anonymize",
		possibleErr:     resourceFileNotFoundErr,
		expectedOutFile: []string{"examples/output/resources_anon_only.json"},
	},
	// tests with possible errors if are not run on env with dot executable
	{
		name: "anonymize-analyze",
		args: "--resource-input-file examples/input/resources.json  --resource-dump-file examples/output/resources_anon.json" +
			" --anonymize --filename examples/output/analysis.txt -o txt",
		possibleErr:     resourceFileNotFoundErr,
		expectedOutFile: []string{"examples/output/resources_anon.json", "examples/output/analysis.svg"},
	},
	{
		name: "analyze-topology-svg",
		args: "--resource-input-file ../pkg/collector/data/json/Example1.json --topology-dump-file" +
			" examples/output/topology.svg --filename examples/output/analysis.svg -o svg" +
			` --output-filter="New-VM-2",New-VM-1`,
		possibleErr:     noDotExecErr,
		expectedOutFile: []string{"examples/output/topology.svg", "examples/output/analysis.svg"},
	},
}

func TestMainStatic(t *testing.T) {
	for _, tt := range staticTests {
		t.Run(tt.name, func(t *testing.T) {
			tt.runTest(t)
		})
	}
}

func (st *cliTest) runTest(t *testing.T) {
	output, err := buildAndExecuteCommand(strings.Split(st.args, " "))
	switch {
	case len(st.expectedErr) > 0:
		countMatch := 0
		for _, errStr := range st.expectedErr {
			if strings.Contains(err.Error(), errStr) {
				countMatch += 1
			}
		}
		require.Greater(t, countMatch, 0)

	case err != nil && st.possibleErr != "":
		// expected err due to env constraints
		require.ErrorContains(t, err, st.possibleErr)
		logging.Debugf("found possibleErr: %s", st.possibleErr)

	default:
		// expecting successful run
		require.Nil(t, err)
		require.Contains(t, output, st.expectedOutputSubstring)
		if len(st.expectedOutFile) > 0 {
			for _, outFile := range st.expectedOutFile {
				_, err := os.Stat(outFile)
				require.Nilf(t, err, "output file %s should exist", st.expectedOutFile)
				// todo: support validation of expected file content
			}
		}
	}
	logging.Debugf("done test %s", st.name)
}

// tests with possible errors if are not run on env with access to nsx manager.
// include collection of nsx resources from API
var nsxEnvTests = []*cliTest{
	{
		name:                    "verbose_analysis_with_no_cli_args",
		args:                    "-v",
		possibleErr:             common.ErrMissingRquiredArg,       // no env vars provided for NSX connection
		expectedOutputSubstring: common.AnalyzedConnectivityHeader, // expecting successful connectivity analysis
	},
	{
		name:            "collect-only",
		args:            "--resource-dump-file examples/output/resources.json --skip-analysis",
		possibleErr:     common.ErrMissingRquiredArg,
		expectedOutFile: []string{"examples/output/resources.json"},
	},
	{
		name:            "collect-anonymize",
		args:            "--resource-dump-file examples/output/resources_anon.json --skip-analysis --anonymize",
		possibleErr:     common.ErrMissingRquiredArg,
		expectedOutFile: []string{"examples/output/resources_anon.json"},
	},
	{
		name: "collect-and-analyze-and-synthesis",
		args: "--resource-dump-file examples/output/collected-resources.json --filename examples/output/collected-analysis.txt" +
			" --synthesis-dump-dir examples/output/collected-synthesis --synthesize-admin-policies",
		possibleErr: common.ErrMissingRquiredArg,
		expectedOutFile: []string{"examples/output/collected-resources.json", "examples/output/collected-analysis.txt",
			"examples/output/collected-synthesis/k8s_resources/policies.yaml"},
	},

	// TODO: add error checks for cases such as partial nsx details in args, partial in env vars..

}

func TestMainNSXEnv(t *testing.T) {
	for _, tt := range nsxEnvTests {
		t.Run(tt.name, func(t *testing.T) {
			tt.runTest(t)
		})
	}
	logging.Debugf("done all nsxEnvTests")
}
