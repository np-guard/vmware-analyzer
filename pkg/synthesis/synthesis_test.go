package synthesis

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

const (
	expectedOutput = "tests_expected_output/"
	carriageReturn = "\r"
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
	err1 := parser.RunParser()
	require.Nil(t, err1)
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	fmt.Println(stringCategoryToSymbolicPolicy(categoryToPolicy))
	expectedOutputFileName := filepath.Join(getTestsDirOut(), a.name+"_PreProcessing.txt")
	expectedOutput, err2 := os.ReadFile(expectedOutputFileName)
	require.Nil(t, err2)
	expectedOutputStr := string(expectedOutput)
	require.Equal(t, cleanStr(stringCategoryToSymbolicPolicy(categoryToPolicy)), cleanStr(expectedOutputStr),
		"output not as expected")
}

func TestPreprocessing(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		test.runPreprocessing(t)
	}
}

func (a *synthesisTest) runConvertToAbstract(t *testing.T) {
	rc := data.ExamplesGeneration(a.exData)
	allowOnlyPolicy, err := NSXToAbstractModelSynthesis(rc)
	require.Nil(t, err)
	fmt.Println(strAllowOnlyPolicy(allowOnlyPolicy))
	expectedOutputFileName := filepath.Join(getTestsDirOut(), a.name+"_ConvertToAbstract.txt")
	expectedOutput, err2 := os.ReadFile(expectedOutputFileName)
	require.Nil(t, err2)
	expectedOutputStr := string(expectedOutput)
	require.Equal(t, cleanStr(strAllowOnlyPolicy(allowOnlyPolicy)), cleanStr(expectedOutputStr),
		"output not as expected")
}

func TestCollectAndConvertToAbstract(t *testing.T) {
	server := collector.NewServerData(os.Getenv("NSX_HOST"), os.Getenv("NSX_USER"), os.Getenv("NSX_PASSWORD"))
	if (server == collector.ServerData{}) {
		fmt.Println("didn't got any server")
		return
	}

	rc, err := collector.CollectResources(server)
	if err != nil {
		t.Errorf("CollectResources() error = %v", err)
		return
	}
	if rc == nil {
		t.Errorf("didnt got resources")
		return
	}

	allowOnlyPolicy, err := NSXToAbstractModelSynthesis(rc)
	require.Nil(t, err)
	fmt.Println(strAllowOnlyPolicy(allowOnlyPolicy))
}

func TestSynthesis(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		test.runConvertToAbstract(t)
	}
}

// getTestsDirOut returns the path to the dir where test output files are located
func getTestsDirOut() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, expectedOutput)
}

// comparison should be insensitive to line comparators; cleaning strings from line comparators
func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "/n", ""), carriageReturn, "")
}
