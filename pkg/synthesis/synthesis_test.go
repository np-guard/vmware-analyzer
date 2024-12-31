package synthesis

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

const (
	expectedOutput = "tests_expected_output/"
	carriageReturn = "\r"
)

const (
	writeFileMde = 0o600
)

type testMode int

const (
	OutputComparison testMode = iota // compare actual output to expected output
	OutputGeneration                 // generate expected output
	OutputIgnore                     // ignore expected output
)

type synthesisTest struct {
	name   string
	exData data.Example
	Mode   testMode
}

var allTests = []synthesisTest{
	{
		name:   "ExampleDumbeldore",
		exData: data.ExampleDumbeldore,
	},
}

func (synTest *synthesisTest) runPreprocessing(t *testing.T) {
	rc := data.ExamplesGeneration(synTest.exData)
	parser := model.NewNSXConfigParserFromResourcesContainer(rc)
	err1 := parser.RunParser()
	require.Nil(t, err1)
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	fmt.Println(stringCategoryToSymbolicPolicy(categoryToPolicy))
	expectedOutputFileName := filepath.Join(getTestsDirOut(), synTest.name+"_PreProcessing.txt")
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

func (synTest *synthesisTest) runConvertToAbstract(t *testing.T, mode testMode) {
	rc := data.ExamplesGeneration(synTest.exData)
	allowOnlyPolicy, err := NSXToAbstractModelSynthesis(rc)
	require.Nil(t, err)
	actualOutput := strAllowOnlyPolicy(allowOnlyPolicy)
	fmt.Println(actualOutput)
	expectedOutputFileName := filepath.Join(getTestsDirOut(), synTest.name+"_ConvertToAbstract.txt")
	compareOrRegenerateOutputPerTest(t, mode, actualOutput, expectedOutputFileName, synTest.name)
	if mode == OutputComparison {
		expectedOutput, err2 := os.ReadFile(expectedOutputFileName)
		require.Nil(t, err2)
		expectedOutputStr := string(expectedOutput)
		require.Equal(t, cleanStr(actualOutput), cleanStr(expectedOutputStr),
			"output not as expected")
	} else if mode == OutputGeneration {
		fmt.Printf("outputGeneration\n")
	}
}

func TestSynthesis(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		test.runConvertToAbstract(t, OutputComparison)
	}
}

func compareOrRegenerateOutputPerTest(t *testing.T, mode testMode, actualOutput, expectedOutputFileName, testName string) {
	if mode == OutputComparison {
		expectedOutput, err := os.ReadFile(expectedOutputFileName)
		require.Nil(t, err)
		expectedOutputStr := string(expectedOutput)
		require.Equal(t, cleanStr(actualOutput), cleanStr(expectedOutputStr),
			fmt.Sprintf("output of test %v not as expected", testName))
	} else if mode == OutputGeneration {
		fmt.Printf("outputGeneration\n")
		err := os.WriteFile(expectedOutputFileName, []byte(actualOutput), writeFileMde)
		require.Nil(t, err)
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
