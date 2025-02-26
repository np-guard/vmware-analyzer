package model_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/data"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/runner"
)

type analyzerTest struct {
	name   string
	exData data.Example
}

var allTests = []analyzerTest{
	{
		name:   "Example1",
		exData: data.Example1,
	},
	{
		name:   "Example1d",
		exData: data.Example1d,
	},
	{
		name:   "Example2",
		exData: data.Example2,
	},
	{
		name:   "Example3",
		exData: data.Example3,
	},
	{
		name:   "ExampleExternal",
		exData: data.Example1External,
	},
	{
		name:   "ExampleDumbeldore",
		exData: data.ExampleDumbeldore,
	},
	{
		name:   "ExampleExclude",
		exData: data.ExampleExclude,
	},
}

func (a *analyzerTest) file() string {
	return a.name + ".txt"
}

func (a *analyzerTest) run(t *testing.T) {
	var overrideAll, overrideOnlyConnOutput bool
	//nolint:gocritic // comment here should stay
	// overrideAll = true // uncommnet to override expected output and config as JSON
	// overrideOnlyConnOutput = true // uncommnet to override expected output
	rc, err := data.ExamplesGeneration(&a.exData, overrideAll)
	require.Nil(t, err)

	runnerObj, err := runner.NewRunnerWithOptionsList(
		runner.WithNSXResources(rc),
		runner.WithHighVerbosity(true),
	)
	require.Nil(t, err)
	err = runnerObj.Run()
	require.Nil(t, err)
	res := runnerObj.GetConnectivityOutput()

	require.Nil(t, err)
	fmt.Println(res)

	expectedFile := getExpectedTestPath(a.file())
	expectedFileExists := true
	if _, err := os.Stat(expectedFile); err != nil {
		expectedFileExists = false
	}
	if overrideAll || overrideOnlyConnOutput || !expectedFileExists {
		err := common.WriteToFile(expectedFile, res)
		require.Nil(t, err)
	} else {
		// compare expected with actual output
		expected, err := os.ReadFile(expectedFile)
		expectedStr := string(expected)
		require.Nil(t, err)
		if expectedStr != res {
			// gen actual output to enable manual diff after test run
			actual := getActualTestPath(a.file())
			err := common.WriteToFile(actual, res)
			require.Nil(t, err)
		}
		require.Equal(t, common.CleanStr(expectedStr), common.CleanStr(res))
	}
	logging.Debugf("done")
}

func TestAnalyzer(t *testing.T) {
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	for i := range allTests {
		test := &allTests[i]
		t.Run(test.name, func(t *testing.T) {
			test.run(t)
		})
	}
}

func getExpectedTestPath(name string) string {
	return filepath.Join(projectpath.Root, "pkg", "data", "expected_output", name)
}

func getActualTestPath(name string) string {
	return filepath.Join(projectpath.Root, "pkg", "data", "actual_output", name)
}
