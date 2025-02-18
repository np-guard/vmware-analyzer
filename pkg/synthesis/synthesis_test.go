package synthesis

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	analyzer "github.com/np-guard/vmware-analyzer/pkg/analyzer"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/tests"
)

const (
	expectedOutput = "tests_expected_output"
	actualOutput   = "tests_actual_output"
	carriageReturn = "\r"
)

type synthesisTest struct {
	name            string
	exData          *tests.ExampleSynthesis
	synthesizeAdmin bool
	noHint          bool // run also with no hint
}

func (synTest *synthesisTest) hints() *symbolicexpr.Hints {
	hintsParm := &symbolicexpr.Hints{GroupsDisjoint: [][]string{}}
	if !synTest.noHint {
		hintsParm.GroupsDisjoint = synTest.exData.DisjointGroupsTags
	}
	return hintsParm
}

// id() creates a uniq id for a synthesisTest, based on its parameter.
// the id is used to create files/directories names
// the prefix is the test name, and labels are added according to the flags values:
func (synTest *synthesisTest) id() string {
	// starting with test name:
	id := synTest.name
	// specify if there is no hints
	if synTest.noHint {
		id += "_NoHint"
	}
	// specify if there are admin policies:
	if synTest.synthesizeAdmin {
		id += "_AdminPoliciesEnabled"
	}
	return id
}

func (synTest *synthesisTest) outDir() string {
	return path.Join(getTestsDirActualOut(), synTest.id())
}
func (synTest *synthesisTest) debugDir() string {
	return path.Join(synTest.outDir(), "debug_dir")
}
func (synTest *synthesisTest) hasExpectedResults() bool {
	return synTest.exData != nil
}
func (synTest *synthesisTest) options() *SynthesisOptions {
	return &SynthesisOptions{
		Hints:           synTest.hints(),
		SynthesizeAdmin: synTest.synthesizeAdmin,
		CreateDNSPolicy: true,
	}
}

var groupsByVmsTests = []synthesisTest{
	{
		name:            "Example1c",
		exData:          &tests.Example1c,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleDumbeldore",
		exData:          &tests.ExampleDumbeldore,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleTwoDeniesSimple",
		exData:          &tests.ExampleTwoDeniesSimple,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleDenyPassSimple",
		exData:          &tests.ExampleDenyPassSimple,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleHintsDisjoint",
		exData:          &tests.ExampleHintsDisjoint,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleHogwartsSimpler",
		exData:          &tests.ExampleHogwartsSimpler,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleHogwartsNoDumbledore",
		exData:          &tests.ExampleHogwartsNoDumbledore,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleHogwarts",
		exData:          &tests.ExampleHogwarts,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleHogwartsAdmin",
		exData:          &tests.ExampleHogwarts,
		synthesizeAdmin: true,
		noHint:          false,
	},
}

var groupsByExprTests = []synthesisTest{
	{
		name:   "ExampleExprSingleScope",
		exData: &tests.ExampleExprSingleScope,
		noHint: false,
	},
	{
		name:   "ExampleExprTwoScopes",
		exData: &tests.ExampleExprTwoScopes,
		noHint: false,
	},
	{
		name:   "ExampleExprAndConds",
		exData: &tests.ExampleExprAndConds,
		noHint: false,
	},
	{
		name:   "ExampleExprOrConds",
		exData: &tests.ExampleExprOrConds,
		noHint: false,
	},
}
var liveNsxTest = synthesisTest{
	name:            "fromCollection",
	exData:          nil,
	synthesizeAdmin: false,
	noHint:          true,
}
var resourceFileTest = synthesisTest{
	name:            "fromResourceFile",
	exData:          nil,
	synthesizeAdmin: false,
	noHint:          true,
}

var allSyntheticTests = append(groupsByVmsTests, groupsByExprTests...)
var allTests = append(allSyntheticTests, []synthesisTest{liveNsxTest, resourceFileTest}...)

///////////////////////////////////////////////////////////////////////
// the tests:
//////////////////////////////////////////////////////////////////////

func TestDoNotAllowSameName(t *testing.T) {
	names := map[string]bool{}
	for _, test := range allTests {
		require.False(t, names[test.name], "There are two tests with the same name %s", names[test.name])
		names[test.name] = true
	}
}
func TestPreprocessing(t *testing.T) {
	parallelTestsRun(t, runPreprocessing)
}
func TestConvertToAbsract(t *testing.T) {
	parallelTestsRun(t, runConvertToAbstract)
}
func TestK8SSynthesis(t *testing.T) {
	parallelTestsRun(t, runK8SSynthesis)
}
func TestCompareNSXConnectivity(t *testing.T) {
	parallelTestsRun(t, runCompareNSXConnectivity)
}

// the TestLiveNSXServer() collect the resource from live nsx server, and call serialTestsRun()
func TestLiveNSXServer(t *testing.T) {
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	server, err := collector.GetNSXServerDate("", "", "")
	if err != nil {
		logging.Debug(err.Error())
		return
	}
	rc, err := collector.CollectResources(server)
	require.Nil(t, err)
	require.NotNil(t, rc)
	serialTestsRun(&liveNsxTest, t, rc)
}

// the TestNsxResourceFile() get the resource from resources.json, and call serialTestsRun()
func TestNsxResourceFile(t *testing.T) {
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	inputFile := filepath.Join(getTestsDirIn(), "resources.json")
	if !common.FileExist(inputFile) {
		logging.Debugf("resource file %s does not exist, nothing to test\n", inputFile)
		return
	}
	b, err := os.ReadFile(inputFile)
	require.Nil(t, err)
	rc, err := collector.FromJSONString(b)
	require.Nil(t, err)
	require.NotNil(t, rc)
	if len(rc.DomainList) == 0 {
		logging.Debugf("%s has no domains\n", inputFile)
		return
	}
	serialTestsRun(&resourceFileTest, t, rc)
}

// ///////////////////////////////////////////////////////////////////////////////////////////////////////
// serialTestsRun() gets a resource, and run the test functions serially
// we need it to be serially, because we have only one resource
func serialTestsRun(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	runPreprocessing(synTest, t, rc)
	runConvertToAbstract(synTest, t, rc)
	runK8SSynthesis(synTest, t, rc)
	runCompareNSXConnectivity(synTest, t, rc)
}

// parallelTestsRun() gets a test function to run, and run it on all the syntheticTests in parallel
func parallelTestsRun(t *testing.T, f func(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel)) {
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	for _, test := range allSyntheticTests {
		rc := data.ExamplesGeneration(&test.exData.FromNSX)
		t.Run(test.name, func(t *testing.T) {
			f(&test, t, rc)
		},
		)
	}
}

//////////////////////////////////////////
// the test functions:
//////////////////////////////////////////

func runPreprocessing(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	err := logging.Tee(path.Join(synTest.debugDir(), "runPreprocessing.log"))
	require.Nil(t, err)
	// get the config:
	parser := analyzer.NewNSXConfigParserFromResourcesContainer(rc)
	err = parser.RunParser()
	require.Nil(t, err)
	config := parser.GetConfig()
	// write the config summary into a file, for debugging:
	configStr := config.GetConfigInfoStr(false)
	err = common.WriteToFile(path.Join(synTest.debugDir(), "config.txt"), configStr)
	require.Nil(t, err)
	// get the preProcess results:
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	preProcessOutput := printPreProcessingSymbolicPolicy(config.Fw.CategoriesSpecs, categoryToPolicy, false)
	logging.Debug(preProcessOutput)
	// write the preProcess results into a file, for debugging:
	err = common.WriteToFile(path.Join(synTest.debugDir(), "pre_process.txt"), preProcessOutput)
	require.Nil(t, err)
	// compare to expected results:
	if synTest.hasExpectedResults() {
		expectedOutputFileName := filepath.Join(getTestsDirExpectedOut(), "pre_process", synTest.id()+".txt")
		compareOrRegenerateOutputPerTest(t, preProcessOutput, expectedOutputFileName, synTest.name)
	}
}

func runConvertToAbstract(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	err := logging.Tee(path.Join(synTest.debugDir(), "runConvertToAbstract.log"))
	require.Nil(t, err)
	abstractModel, err := NSXToPolicy(rc, nil, synTest.options())
	require.Nil(t, err)
	abstractModelStr := strAllowOnlyPolicy(abstractModel.policy[0], false)
	// write the abstract model rules into a file, for debugging:
	err = common.WriteToFile(path.Join(synTest.debugDir(), "abstract_model.txt"), abstractModelStr)
	require.Nil(t, err)
	// compare to expected results:
	if synTest.hasExpectedResults() {
		expectedOutputFileName := filepath.Join(getTestsDirExpectedOut(), "abstract_models", synTest.id()+".txt")
		compareOrRegenerateOutputPerTest(t, abstractModelStr, expectedOutputFileName, synTest.name)
	}
}

func runK8SSynthesis(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	err := logging.Tee(path.Join(synTest.debugDir(), "runK8SSynthesis.log"))
	require.Nil(t, err)
	k8sDir := path.Join(synTest.outDir(), k8sResourcesDir)
	// create K8S resources:
	resources, err := NSXToK8sSynthesis(rc, nil, synTest.options())
	require.Nil(t, err)
	err = resources.CreateDir(synTest.outDir())
	require.Nil(t, err)
	// run netpol-analyzer, the connectivity is kept into a file, for debugging:
	// todo - compare the k8s_connectivity.txt with vmware_connectivity.txt (currently they are not in the same format)
	err = os.MkdirAll(synTest.debugDir(), os.ModePerm)
	require.Nil(t, err)
	err = k8sAnalyzer(k8sDir, path.Join(synTest.debugDir(), "k8s_connectivity.txt"), "txt")
	require.Nil(t, err)
	// todo: WA until https://github.com/np-guard/vmware-analyzer/issues/235 is fixed
	if synTest.name == "ExampleExprAndConds" || synTest.name == "ExampleExprOrConds" {
		return
	}
	// compare to expected results:
	if synTest.hasExpectedResults() {
		expectedOutputDir := filepath.Join(getTestsDirExpectedOut(), k8sResourcesDir, synTest.id())
		compareOrRegenerateOutputDirPerTest(t, k8sDir, expectedOutputDir, synTest.name)
	}
}

func runCompareNSXConnectivity(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	err := logging.Tee(path.Join(synTest.debugDir(), "runCompareNSXConnectivity.log"))
	require.Nil(t, err)
	debugDir := synTest.debugDir()
	// store the original NSX resources in JSON, for debugging:
	jsonOut, err := rc.ToJSONString()
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "nsx_resources.json"), jsonOut)
	require.Nil(t, err)

	// getting the vmware connectivity
	_, connectivity, err := analyzer.NSXConnectivityFromResourcesContainer(rc, common.OutputParameters{Format: "txt"})
	require.Nil(t, err)
	// write to file, for debugging:
	err = common.WriteToFile(path.Join(debugDir, "vmware_connectivity.txt"), connectivity)
	require.Nil(t, err)

	// create abstract model convert it to a new equiv NSX resources:
	abstractModel, err := NSXToPolicy(rc, nil, synTest.options())
	require.Nil(t, err)
	policies, groups := toNSXPolicies(rc, abstractModel)
	// merge the generate resources into the orig resources. store in into JSON config in a file, for debugging::
	rc.DomainList[0].Resources.SecurityPolicyList = policies                                       // override policies
	rc.DomainList[0].Resources.GroupList = append(rc.DomainList[0].Resources.GroupList, groups...) // update groups
	jsonOut, err = rc.ToJSONString()
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_resources.json"), jsonOut)
	require.Nil(t, err)

	// run the analyzer on the new NSX config (from abstract), and store in text file
	_, analyzed, err := analyzer.NSXConnectivityFromResourcesContainer(rc, common.OutputParameters{Format: "txt"})
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_connectivity.txt"), analyzed)
	require.Nil(t, err)

	// the validation of the abstract model conversion is here:
	// validate connectivity analysis is the same for the new (from abstract) and original NSX configs
	require.Equal(t, connectivity, analyzed,
		fmt.Sprintf("nsx and vmware connectivities of test %v are not equal", t.Name()))
}

// /////////////////////////////////////////////////////////////////////
// some directory related functions:
// ////////////////////////////////////////////////////////////////////
func getTestsDirExpectedOut() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, expectedOutput)
}
func getTestsDirActualOut() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, actualOutput)
}
func getTestsDirIn() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, "tests")
}

// /////////////////////////////////////////////////////////////////////////
// comparing / generating files and dirs:
// /////////////////////////////////////////////////////////////////////////
type testMode int

const (
	OutputComparison testMode = iota // compare actual output to expected output
	OutputGeneration                 // generate expected output
)

// to generate output results change runTestMode:
const runTestMode = OutputComparison

func compareOrRegenerateOutputDirPerTest(t *testing.T, actualDir, expectedDir, testName string) {
	actualFiles, err := os.ReadDir(actualDir)
	require.Nil(t, err)
	if runTestMode == OutputComparison {
		expectedFiles, err := os.ReadDir(expectedDir)
		require.Nil(t, err)
		require.Equal(t, len(actualFiles), len(expectedFiles),
			fmt.Sprintf("number of output files of test %v not as expected", testName))
		for _, file := range actualFiles {
			expectedOutput, err := os.ReadFile(filepath.Join(expectedDir, file.Name()))
			require.Nil(t, err)
			actualOutput, err := os.ReadFile(filepath.Join(actualDir, file.Name()))
			require.Nil(t, err)
			require.Equal(t, common.CleanStr(string(actualOutput)), common.CleanStr(string(expectedOutput)),
				fmt.Sprintf("output file %s of test %v not as expected", file.Name(), testName))
		}
	} else if runTestMode == OutputGeneration {
		err := os.RemoveAll(expectedDir)
		require.Nil(t, err)
		err = os.CopyFS(expectedDir, os.DirFS(actualDir))
		require.Nil(t, err)
	}
}

func compareOrRegenerateOutputPerTest(t *testing.T, actualOutput, expectedOutputFileName, testName string) {
	if runTestMode == OutputComparison {
		expectedOutput, err := os.ReadFile(expectedOutputFileName)
		require.Nil(t, err)
		expectedOutputStr := string(expectedOutput)
		require.Equal(t, common.CleanStr(actualOutput), common.CleanStr(expectedOutputStr),
			fmt.Sprintf("output of test %v not as expected", testName))
	} else if runTestMode == OutputGeneration {
		err := common.WriteToFile(expectedOutputFileName, actualOutput)
		require.Nil(t, err)
	}
}
