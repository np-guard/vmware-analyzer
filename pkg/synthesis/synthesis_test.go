package synthesis

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
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
	name                  string
	exData                tests.ExampleSynthesis
	allowOnlyFromCategory dfw.DfwCategory
	noHint                bool // run also with no hint
}

var allTests = []synthesisTest{
	{
		name:                  "ExampleDumbeldore",
		exData:                tests.ExampleDumbeldore,
		allowOnlyFromCategory: 0,
		noHint:                true,
	},
	{
		name:                  "ExampleTwoDeniesSimple",
		exData:                tests.ExampleTwoDeniesSimple,
		allowOnlyFromCategory: 0,
		noHint:                true,
	},
	{
		name:                  "ExampleDenyPassSimple",
		exData:                tests.ExampleDenyPassSimple,
		allowOnlyFromCategory: 0,
		noHint:                true,
	},
	{
		name:                  "ExampleHintsDisjoint",
		exData:                tests.ExampleHintsDisjoint,
		allowOnlyFromCategory: 0,
		noHint:                true,
	},
	{
		name:                  "ExampleHogwartsSimpler",
		exData:                tests.ExampleHogwartsSimpler,
		allowOnlyFromCategory: 0,
		noHint:                true,
	},
	{
		name:                  "ExampleHogwartsNoDumbledore",
		exData:                tests.ExampleHogwartsNoDumbledore,
		allowOnlyFromCategory: 0,
		noHint:                false,
	},
	{
		name:                  "ExampleHogwarts",
		exData:                tests.ExampleHogwarts,
		allowOnlyFromCategory: 0,
		noHint:                false,
	},
	{
		name:                  "ExampleHogwarts",
		exData:                tests.ExampleHogwarts,
		allowOnlyFromCategory: dfw.AppCategoty,
		noHint:                false,
	},
}

func (synTest *synthesisTest) runPreprocessing(t *testing.T, mode testMode) {
	rc := data.ExamplesGeneration(&synTest.exData.FromNSX)
	parser := model.NewNSXConfigParserFromResourcesContainer(rc)
	err1 := parser.RunParser()
	require.Nil(t, err1)
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	actualOutput := stringCategoryToSymbolicPolicy(config.Fw.CategoriesSpecs, categoryToPolicy)
	fmt.Println(actualOutput)
	suffix := "_PreProcessing"
	if synTest.allowOnlyFromCategory > 0 {
		suffix = fmt.Sprintf("%v_%s", suffix, synTest.allowOnlyFromCategory)
	}
	expectedOutputFileName := filepath.Join(getTestsDirOut(), synTest.name+suffix+".txt")
	compareOrRegenerateOutputPerTest(t, mode, actualOutput, expectedOutputFileName, synTest.name)
}

func TestPreprocessing(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		// to generate output comment the following line and uncomment the one after
		test.runPreprocessing(t, OutputComparison)
		//nolint:gocritic // uncomment for generating output
		//test.runPreprocessing(t, OutputGeneration)
	}
}

func (synTest *synthesisTest) runConvertToAbstract(t *testing.T, mode testMode) {
	rc := data.ExamplesGeneration(&synTest.exData.FromNSX)
	hintsParm := &symbolicexpr.Hints{GroupsDisjoint: [][]string{}}
	suffix := "_ConvertToAbstractNoHint.txt"
	if !synTest.noHint {
		hintsParm.GroupsDisjoint = synTest.exData.DisjointGroups
		suffix = "_ConvertToAbstract.txt"
	}
	if synTest.allowOnlyFromCategory > 0 {
		suffix = fmt.Sprintf("%v_%s", suffix, synTest.allowOnlyFromCategory)
	}
	fmt.Println("suffix:", suffix)
	outDir := path.Join("out", synTest.name)
	abstractModel, err := NSXToK8sSynthesis(rc, outDir, hintsParm, synTest.allowOnlyFromCategory)
	require.Nil(t, err)
	addDebugFiles(t, rc, abstractModel, outDir)
	expectedOutputFileName := filepath.Join(getTestsDirOut(), synTest.name+suffix)
	actualOutput := strAllowOnlyPolicy(abstractModel.policy[0])
	fmt.Println(actualOutput)
	compareOrRegenerateOutputPerTest(t, mode, actualOutput, expectedOutputFileName, synTest.name)
}
func addDebugFiles(t *testing.T, rc *collector.ResourcesContainerModel, abstractModel *AbstractModelSyn, outDir string) {
	for _, format := range []string{"txt", "dot"} {
		params := common.OutputParameters{
			Format: format,
		}
		analyzed, err := model.NSXConnectivityFromResourcesContainer(rc, params)
		require.Nil(t, err)
		err = common.WriteToFile(path.Join(outDir, "vmware_connectivity."+format), analyzed)
		require.Nil(t, err)
	}
	actualOutput := strAllowOnlyPolicy(abstractModel.policy[0])
	err := common.WriteToFile(path.Join(outDir, "abstract_model.txt"), actualOutput)
	require.Nil(t, err)
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
	outDir := path.Join("out", "from_collection")
	abstractModel, err := NSXToK8sSynthesis(rc, outDir,
		&symbolicexpr.Hints{GroupsDisjoint: [][]string{}}, 0)
	require.Nil(t, err)
	fmt.Println(strAllowOnlyPolicy(abstractModel.policy[0]))
	addDebugFiles(t, rc, abstractModel, outDir)
	require.Nil(t, err)
}

func TestConvertToAbsract(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		// to generate output comment the following line and uncomment the one after
		test.runConvertToAbstract(t, OutputComparison)
		//nolint:gocritic // uncomment for generating output
		//test.runConvertToAbstract(t, OutputGeneration)
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
	return strings.ReplaceAll(strings.ReplaceAll(str, "\n", ""), carriageReturn, "")
}
