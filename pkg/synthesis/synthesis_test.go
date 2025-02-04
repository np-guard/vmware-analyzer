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
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/tests"
)

const (
	expectedOutput = "tests_expected_output"
	actualOutput   = "tests_actual_output"
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

const runTestMode = OutputComparison

type synthesisTest struct {
	name                  string
	exData                tests.ExampleSynthesis
	allowOnlyFromCategory collector.DfwCategory // category to start the "allow-only" conversion from
	noHint                bool                  // run also with no hint
}

func (synTest *synthesisTest) hints() *symbolicexpr.Hints {
	hintsParm := &symbolicexpr.Hints{GroupsDisjoint: [][]string{}}
	if !synTest.noHint {
		hintsParm.GroupsDisjoint = synTest.exData.DisjointGroups
	}
	return hintsParm
}
func (synTest *synthesisTest) ID(tName string) string {
	name := fmt.Sprintf("%s_%s", synTest.name, tName)
	if synTest.noHint {
		name += "NoHint"
	}
	if synTest.allowOnlyFromCategory > 0 {
		name = fmt.Sprintf("%v_%s", name, synTest.allowOnlyFromCategory)
	}
	return name
}

var groupsByVmsTests = []synthesisTest{
	{
		name:                  "Example1c",
		exData:                tests.Example1c,
		allowOnlyFromCategory: collector.MinCategory(),
		noHint:                true,
	},
	{
		name:                  "ExampleDumbeldore",
		exData:                tests.ExampleDumbeldore,
		allowOnlyFromCategory: collector.MinCategory(),
		noHint:                true,
	},
	{
		name:                  "ExampleTwoDeniesSimple",
		exData:                tests.ExampleTwoDeniesSimple,
		allowOnlyFromCategory: collector.MinCategory(),
		noHint:                true,
	},
	{
		name:                  "ExampleDenyPassSimple",
		exData:                tests.ExampleDenyPassSimple,
		allowOnlyFromCategory: collector.MinCategory(),
		noHint:                true,
	},
	{
		name:                  "ExampleHintsDisjoint",
		exData:                tests.ExampleHintsDisjoint,
		allowOnlyFromCategory: collector.MinCategory(),
		noHint:                true,
	},
	{
		name:                  "ExampleHogwartsSimpler",
		exData:                tests.ExampleHogwartsSimpler,
		allowOnlyFromCategory: collector.MinCategory(),
		noHint:                true,
	},
	{
		name:                  "ExampleHogwartsNoDumbledore",
		exData:                tests.ExampleHogwartsNoDumbledore,
		allowOnlyFromCategory: collector.MinCategory(),
		noHint:                false,
	},
	{
		name:                  "ExampleHogwarts",
		exData:                tests.ExampleHogwarts,
		allowOnlyFromCategory: collector.MinCategory(),
		noHint:                false,
	},
	{
		name:                  "ExampleHogwartsAppCategory",
		exData:                tests.ExampleHogwarts,
		allowOnlyFromCategory: collector.AppCategoty,
		noHint:                false,
	},
}

var groupsByExprTests = []synthesisTest{
	{
		name:   "ExampleExprSingleScope",
		exData: tests.ExampleExprSingleScope,
		noHint: false,
	},
	{
		name:   "ExampleExprTwoScopes",
		exData: tests.ExampleExprTwoScopes,
		noHint: false,
	},
	{
		name:   "ExampleExprAndConds",
		exData: tests.ExampleExprAndConds,
		noHint: false,
	},
	{
		name:   "ExampleExprOrConds",
		exData: tests.ExampleExprOrConds,
		noHint: false,
	},
}
var allTests = append(groupsByVmsTests, groupsByExprTests...)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// getTestsDirExpectedOut returns the path to the dir where test output files are located
func getTestsDirExpectedOut() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, expectedOutput)
}
func getTestsDirActualOut() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, actualOutput)
}

func (synTest *synthesisTest) outDir() string {
	return path.Join(getTestsDirActualOut(), synTest.ID(""))
}
func (synTest *synthesisTest) debugDir() string {
	return path.Join(synTest.outDir(), "debug_files")
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestDoNotAllowSameName(t *testing.T) {
	names := map[string]bool{}
	for _, test := range allTests {
		require.False(t, names[test.name], "There are two tests with the same name %s", names[test.name])
		names[test.name] = true
	}
}

func (synTest *synthesisTest) runPreprocessing(t *testing.T, mode testMode) {
	rc := data.ExamplesGeneration(&synTest.exData.FromNSX)
	parser := model.NewNSXConfigParserFromResourcesContainer(rc)
	err := parser.RunParser()
	require.Nil(t, err)
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	actualOutput := stringCategoryToSymbolicPolicy(config.Fw.CategoriesSpecs, categoryToPolicy)
	fmt.Println(actualOutput)
	testID := synTest.ID("PreProcessing")
	expectedOutputFileName := filepath.Join(getTestsDirExpectedOut(), "pre_process", testID+".txt")
	compareOrRegenerateOutputPerTest(t, mode, actualOutput, expectedOutputFileName, synTest.name)
}

func (synTest *synthesisTest) runConvertToAbstract(t *testing.T, mode testMode) {
	rc := data.ExamplesGeneration(&synTest.exData.FromNSX)
	testID := synTest.ID("ConvertToAbstract")
	abstractModel, err := NSXToPolicy(rc, synTest.hints(), synTest.allowOnlyFromCategory)
	expectedOutputFileName := filepath.Join(getTestsDirExpectedOut(), "abstract_models", testID+".txt")
	require.Nil(t, err)
	actualOutput := strAllowOnlyPolicy(abstractModel.policy[0])
	fmt.Println(actualOutput)

	// write the config summery into a file
	configStr, err := model.NSXConfigStrFromResourcesContainer(rc, common.OutputParameters{})
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(synTest.debugDir(), "config.txt"), configStr)
	require.Nil(t, err)
	// write the abstract model rules into a file
	err = common.WriteToFile(path.Join(synTest.debugDir(), "abstract_model.txt"), actualOutput)
	require.Nil(t, err)
	compareOrRegenerateOutputPerTest(t, mode, actualOutput, expectedOutputFileName, synTest.name)
}

func (synTest *synthesisTest) runK8SSynthesis(t *testing.T, mode testMode) {
	rc := data.ExamplesGeneration(&synTest.exData.FromNSX)
	testID := synTest.ID("K8S")
	k8sDir := path.Join(synTest.outDir(), k8sResourcesDir)
	err := NSXToK8sSynthesis(rc, synTest.outDir(), synTest.hints(), synTest.allowOnlyFromCategory)
	require.Nil(t, err)
	expectedOutputDir := filepath.Join(getTestsDirExpectedOut(), k8sResourcesDir, testID)
	compareOrRegenerateOutputDirPerTest(t, mode, k8sDir, expectedOutputDir, synTest.name)
	// run netpol-analyzer
	// todo - compare the k8s_connectivity.txt with vmware_connectivity.txt (currently they are not in the same format)
	err = os.MkdirAll(synTest.debugDir(), os.ModePerm)
	require.Nil(t, err)
	err = k8sAnalyzer(k8sDir, path.Join(synTest.debugDir(), "k8s_connectivity.txt"), "txt")
	require.Nil(t, err)
}

func (synTest *synthesisTest) runCompareNSXConnectivity(t *testing.T) {
	debugDir := synTest.debugDir()
	rc := data.ExamplesGeneration(&synTest.exData.FromNSX)
	// store the original NSX resources in JSON
	jsonOut, err := rc.ToJSONString()
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "nsx_resources.json"), jsonOut)
	require.Nil(t, err)

	// getting the vmware connectivity
	abstractModel, err := NSXToPolicy(rc, synTest.hints(), synTest.allowOnlyFromCategory)
	require.Nil(t, err)
	connectivity, err := model.NSXConnectivityFromResourcesContainer(rc, common.OutputParameters{Format: "txt"})
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "vmware_connectivity.txt"), connectivity)
	require.Nil(t, err)

	// convert the abstract model to a new equiv NSX config
	policies, groups := toNSXPolicies(rc, abstractModel)
	rc.DomainList[0].Resources.SecurityPolicyList = policies                                       // override policies
	rc.DomainList[0].Resources.GroupList = append(rc.DomainList[0].Resources.GroupList, groups...) // update groups
	jsonOut, err = rc.ToJSONString()
	require.Nil(t, err)
	// store the *new* (from abstract model) NSX JSON config in a file
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_resources.json"), jsonOut)
	require.Nil(t, err)

	// run the analyzer on the new NSX config (from abstract), and store in text file
	analyzed, err := model.NSXConnectivityFromResourcesContainer(rc, common.OutputParameters{Format: "txt"})
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_connectivity.txt"), analyzed)
	require.Nil(t, err)

	// the validation of the abstract model conversion is here:
	// validate connectivity analysis is the same for the new (from abstract) and original NSX configs
	require.Equal(t, connectivity, analyzed,
		fmt.Sprintf("nsx and vmware connectivities of test %v are not equal", t.Name()))
}

// ///////////////////////////////////////////////////////////////////////////////////////////////////////

// to be run only on "live nsx" mode
// no expected output is tested
// only generates
// (1) converted config into k8s network policies
// (2) equiv config in NSX with allow-only DFW rules, as derived from the abstract model
// and validates that connectivity of orign and new NSX configs are the same
func TestCollectAndConvertToAbstract(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	server, err := collector.GetNSXServerDate("", "", "")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	rc, err := collector.CollectResources(server)
	if err != nil {
		t.Errorf("CollectResources() error = %v", err)
		return
	}
	if rc == nil {
		t.Errorf(common.ErrNoResources)
		return
	}
	outDir := path.Join("out", "from_collection")
	err = NSXToK8sSynthesis(rc, outDir, &symbolicexpr.Hints{GroupsDisjoint: [][]string{}}, 0)
	require.Nil(t, err)
	// addDebugFiles(t, rc, abstractModel, outDir)
	require.Nil(t, err)
}

// ///////////////////////////////////////////////////////////////////////////////////////////////////////
func TestConvertToAbsract(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for _, test := range groupsByVmsTests {
		t.Run(test.name, func(t *testing.T) {
			test.runConvertToAbstract(t, runTestMode)
		},
		)
	}
}
func TestK8SSynthesis(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for _, test := range groupsByVmsTests {
		t.Run(test.name, func(t *testing.T) {
			test.runK8SSynthesis(t, runTestMode)
		},
		)
	}
}

func TestPreprocessing(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for _, test := range groupsByVmsTests {
		t.Run(test.name, func(t *testing.T) {
			test.runPreprocessing(t, runTestMode)
		},
		)
	}
}

func TestCompareNSXConnectivity(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for _, test := range groupsByVmsTests {
		t.Run(test.name, func(t *testing.T) {
			test.runCompareNSXConnectivity(t)
		},
		)
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

func compareOrRegenerateOutputDirPerTest(t *testing.T, mode testMode, actualDir, expectedDir, testName string) {
	actualFiles, err := os.ReadDir(actualDir)
	require.Nil(t, err)
	if mode == OutputComparison {
		expectedFiles, err := os.ReadDir(expectedDir)
		require.Nil(t, err)
		require.Equal(t, len(actualFiles), len(expectedFiles),
			fmt.Sprintf("number of output files of test %v not as expected", testName))
		for _, file := range actualFiles {
			expectedOutput, err := os.ReadFile(filepath.Join(expectedDir, file.Name()))
			require.Nil(t, err)
			actualOutput, err := os.ReadFile(filepath.Join(actualDir, file.Name()))
			require.Nil(t, err)
			require.Equal(t, cleanStr(string(actualOutput)), cleanStr(string(expectedOutput)),
				fmt.Sprintf("output file %s of test %v not as expected", file.Name(), testName))
		}
	} else if mode == OutputGeneration {
		err := os.RemoveAll(expectedDir)
		require.Nil(t, err)
		err = os.CopyFS(expectedDir, os.DirFS(actualDir))
		require.Nil(t, err)
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

// comparison should be insensitive to line comparators; cleaning strings from line comparators
func cleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, "\n", ""), carriageReturn, "")
}

// todo tmp until expr fully supported by synthesis
func (synTest *synthesisTest) runTmpWithExpr() {
	fmt.Printf("\ntest:%v\n~~~~~~~~~~~~~~~~~~~~~~~~~~~\nrc.VirtualMachineList:\n", synTest.name)
	rc := data.ExamplesGeneration(&synTest.exData.FromNSX)
	for i := range rc.DomainList[0].Resources.GroupList {
		expr := rc.DomainList[0].Resources.GroupList[i].Expression
		fmt.Printf("group: %v ", rc.DomainList[0].Resources.GroupList[i].Name())
		if expr != nil {
			fmt.Printf("of expression %v\n", rc.DomainList[0].Resources.GroupList[i].Expression.String())
		} else {
			fmt.Printf("has no expression; must be defined by vms\n")
		}
	}
}

func TestTmpExpr(t *testing.T) {
	for i := range allTests {
		test := &allTests[i]
		test.runTmpWithExpr()
	}
}
