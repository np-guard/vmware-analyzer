package model

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
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
		name:   "Example2",
		exData: data.Example2,
	},
	{
		name:   "Example3",
		exData: data.Example3,
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
	rc := data.ExamplesGeneration(&a.exData)
	err := a.exData.StoreAsJSON(overrideAll)
	require.Nil(t, err)

	res, err := NSXConnectivityFromResourcesContainerPlainText(rc)
	require.Nil(t, err)
	fmt.Println(res)

	expectedFile := getExpectedTestPath(a.file())
	if overrideAll || overrideOnlyConnOutput {
		err := os.WriteFile(expectedFile, []byte(res), 0o600)
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
		require.Equal(t, cleanStr(expectedStr), cleanStr(res))
	}
	fmt.Println("done")
}
func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "\n", ""), "\r", "")
}

func TestAnalyzer(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		test.run(t)
	}
}

func getExpectedTestPath(name string) string {
	return filepath.Join(projectpath.Root, "pkg", "collector", "data", "expected_output", name)
}

func getActualTestPath(name string) string {
	return filepath.Join(projectpath.Root, "pkg", "collector", "data", "actual_output", name)
}
