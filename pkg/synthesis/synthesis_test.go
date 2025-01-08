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
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/tests"
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
)

type synthesisTest struct {
	name   string
	exData tests.ExampleSynthesis
	Mode   testMode
}

var allTests = []synthesisTest{
	{
		name:   "ExampleDumbeldore",
		exData: tests.ExampleDumbeldore,
	},
	{
		name:   "ExampleTwoDeniesSimple",
		exData: tests.ExampleTwoDeniesSimple,
	},
	{
		name:   "ExampleDenyPassSimple",
		exData: tests.ExampleDenyPassSimple,
	},
	{
		name:   "ExampleHintsDisjoint",
		exData: tests.ExampleHintsDisjoint,
	},
	{
		name:   "ExampleHogwartsSimpler",
		exData: tests.ExampleHogwartsSimpler,
	},
	{
		name:   "ExampleHogwartsNoDumbledore",
		exData: tests.ExampleHogwartsNoDumbledore,
	},
}

func (synTest *synthesisTest) runPreprocessing(t *testing.T, mode testMode) {
	rc := data.ExamplesGeneration(synTest.exData.FromNSX)
	parser := model.NewNSXConfigParserFromResourcesContainer(rc)
	err1 := parser.RunParser()
	require.Nil(t, err1)
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	actualOutput := stringCategoryToSymbolicPolicy(config.Fw.CategoriesSpecs, categoryToPolicy)
	fmt.Println(actualOutput)
	expectedOutputFileName := filepath.Join(getTestsDirOut(), synTest.name+"_PreProcessing.txt")
	compareOrRegenerateOutputPerTest(t, mode, actualOutput, expectedOutputFileName, synTest.name)
}

func TestPreprocessing(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		// to generate output comment the following line and uncomment the one after
		//test.runPreprocessing(t, OutputComparison)
		//nolint:gocritic // uncomment for generating output
		test.runPreprocessing(t, OutputGeneration)
	}
}

func (synTest *synthesisTest) runConvertToAbstract(t *testing.T, mode testMode, withHints bool) {
	rc := data.ExamplesGeneration(synTest.exData.FromNSX)
	hintsParm := &symbolicexpr.Hints{GroupsDisjoint: [][]string{}}
	suffix := "_ConvertToAbstractNoHint.txt"
	if withHints {
		hintsParm.GroupsDisjoint = synTest.exData.DisjointGroups
		suffix = "_ConvertToAbstract.txt"
	}
	allowOnlyPolicy, err := NSXToAbstractModelSynthesis(rc, hintsParm)
	require.Nil(t, err)
	actualOutput := strAllowOnlyPolicy(allowOnlyPolicy)
	fmt.Println(actualOutput)
	expectedOutputFileName := filepath.Join(getTestsDirOut(), synTest.name+suffix)
	compareOrRegenerateOutputPerTest(t, mode, actualOutput, expectedOutputFileName, synTest.name)
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

	allowOnlyPolicy, err := NSXToAbstractModelSynthesis(rc, &symbolicexpr.Hints{GroupsDisjoint: [][]string{}})
	require.Nil(t, err)
	fmt.Println(strAllowOnlyPolicy(allowOnlyPolicy))
}

func TestConvertToAbsract(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		// to generate output comment the following line and uncomment the one after
		test.runConvertToAbstract(t, OutputComparison, true)
		//test.runConvertToAbstract(t, OutputComparison, false)
		//nolint:gocritic // uncomment for generating output
		//test.runConvertToAbstract(t, OutputGeneration, true)
		//test.runConvertToAbstract(t, OutputGeneration, false)
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
