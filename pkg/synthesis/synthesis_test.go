package synthesis

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

// todo...
const (
	examplesDir  = "examples/"
	synthesisDir = "input/"
	outDir       = "out/"
)

type synthesisTest struct {
	name   string
	exData data.Example
}

var allTests = []synthesisTest{
	{
		name:   "ExampleDumbeldore",
		exData: data.ExampleDumbeldore,
	},
}

func (a *synthesisTest) runPreprocessing(t *testing.T) {
	rc := data.ExamplesGeneration(a.exData)
	parser := model.NewNSXConfigParserFromResourcesContainer(rc)
	err := parser.RunParser()
	require.Nil(t, err)
	config := parser.GetConfig()
	policy := preProcessing(config.Fw.CategoriesSpecs)
	fmt.Println(policy.string())
	// todo: test via comparing output to files in a separate PR (issue with window in analyzer tests)
}

func TestPreprocessing(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		test.runPreprocessing(t)
	}
}

// getTestsDirOut returns the path to the dir where test output files are located
func getTestsDirOut(testDir string) string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, examplesDir+outDir+testDir)
}
