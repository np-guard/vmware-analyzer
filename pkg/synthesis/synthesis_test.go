package synthesis

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	analyzer "github.com/np-guard/vmware-analyzer/pkg/analyzer"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/data"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
)

const (
	expectedOutput = "tests_expected_output"
	actualOutput   = "tests_actual_output"
)

var defaultParams = common.OutputParameters{Format: "txt"}

type synthesisTest struct {
	name            string
	exData          *data.Example
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
		exData:          data.Example1c,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "Example1External",
		exData:          data.Example1External,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "Example1dExternalWithSegments",
		exData:          data.Example1dExternalWithSegments,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleExternalWithDenySimple",
		exData:          data.ExampleExternalWithDenySimple,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleExternalSimpleWithInterlDenyAllow",
		exData:          data.ExampleExternalSimpleWithInterlDenyAllow,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleExternalSimpleWithInterlDenyAllowAdmin",
		exData:          data.ExampleExternalSimpleWithInterlDenyAllow,
		synthesizeAdmin: true,
		noHint:          true,
	},
	{
		name:            "ExampleInternalWithInterDenyAllow",
		exData:          data.ExampleInternalWithInterDenyAllow,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleInternalWithInterDenyAllowWithSegments",
		exData:          data.ExampleInternalWithInterDenyAllowWithSegments,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleHogwartsExternal",
		exData:          data.ExampleHogwartsExternal,
		noHint:          false,
		synthesizeAdmin: false,
	},
	{
		name:            "ExampleHogwartsExternalAdmin",
		exData:          data.ExampleHogwartsExternal,
		noHint:          false,
		synthesizeAdmin: true,
	},
	{
		name:            "ExampleDumbeldore",
		exData:          data.ExampleDumbeldore,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleTwoDeniesSimple",
		exData:          data.ExampleTwoDeniesSimple,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleDenyPassSimple",
		exData:          data.ExampleDenyPassSimple,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleHintsDisjoint_NoHint",
		exData:          data.ExampleHintsDisjoint,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleHintsDisjoint",
		exData:          data.ExampleHintsDisjoint,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleHogwartsSimpler",
		exData:          data.ExampleHogwartsSimpler,
		synthesizeAdmin: false,
		noHint:          true,
	},
	{
		name:            "ExampleHogwartsNoDumbledore",
		exData:          data.ExampleHogwartsNoDumbledore,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleHogwarts",
		exData:          data.ExampleHogwarts,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleHogwartsAdmin",
		exData:          data.ExampleHogwarts,
		synthesizeAdmin: true,
		noHint:          false,
	},
	{
		name:            "ExampleHogwartsSimplerNonSymInOutAdmin",
		exData:          data.ExampleHogwartsSimplerNonSymInOut,
		synthesizeAdmin: true,
		noHint:          false,
	},
}

var groupsByExprTests = []synthesisTest{
	{
		name:   "ExampleExprSingleScope",
		exData: data.ExampleExprSingleScope,
		noHint: false,
	},
	{
		name:   "ExampleExprTwoScopes",
		exData: data.ExampleExprTwoScopes,
		noHint: false,
	},
	{
		name:   "ExampleExprTwoScopesAbstract",
		exData: data.ExampleExprTwoScopesAbstract,
		noHint: false,
	},
	{
		name:   "ExampleExprAndConds",
		exData: data.ExampleExprAndConds,
		noHint: false,
	},
	{
		name:   "ExampleExprOrConds",
		exData: data.ExampleExprOrConds,
		noHint: false,
	},
	{
		name:            "ExampleExprAndCondsAdmin",
		exData:          data.ExampleExprAndConds,
		noHint:          false,
		synthesizeAdmin: true,
	},
	{
		name:            "ExampleExprOrCondsAdmin",
		exData:          data.ExampleExprOrConds,
		noHint:          false,
		synthesizeAdmin: true,
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

// //////////////////////////////////////////////////////////////////////
type testMethod func(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel)

func (f testMethod) name() string {
	name := strings.Split(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name(), ".")
	return name[len(name)-1]
}

var testsMethods = []testMethod{
	runPreprocessing,
	runConvertToAbstract,
	runK8SSynthesis,
	runK8STraceFlow,
	runCompareNSXConnectivity,
}

///////////////////////////////////////////////////////////////////////
// the tests:
//////////////////////////////////////////////////////////////////////

func TestDoNotAllowSameName(t *testing.T) {
	names := map[string]bool{}
	for _, test := range allTests {
		require.False(t, names[test.name], "There are two tests with the same name %s", test.name)
		names[test.name] = true
	}
}

func TestPreprocessing(t *testing.T) {
	subTestsRunByTestName(t, runPreprocessing)
}
func TestConvertToAbsract(t *testing.T) {
	subTestsRunByTestName(t, runConvertToAbstract)
}
func TestK8SSynthesis(t *testing.T) {
	subTestsRunByTestName(t, runK8SSynthesis)
}
func TestK8STraceFlow(t *testing.T) {
	subTestsRunByTestName(t, runK8STraceFlow)
}
func TestCompareNSXConnectivity(t *testing.T) {
	subTestsRunByTestName(t, runCompareNSXConnectivity)
}

// the TestLiveNSXServer() collect the resource from live nsx server, and call serialTestsRun()
func TestLiveNSXServer(t *testing.T) {
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	server, err := collector.GetNSXServerDate("", "", "", true)
	if err != nil {
		logging.Debug(err.Error())
		return
	}
	rc, err := collector.CollectResources(server)
	require.Nil(t, err)
	require.NotNil(t, rc)
	// since collection is long, here the test methods does not run as subtest
	for _, f := range testsMethods {
		f(&liveNsxTest, t, rc)
	}
}

// the TestNsxResourceFile() get the resource from resources.json, and run the testsMethods on it
func TestNsxResourceFile(t *testing.T) {
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	rc := readUserResourceFile(t)
	if rc == nil {
		return
	}
	// running each test method as a sub test with method name:
	for _, f := range testsMethods {
		t.Run(f.name(), func(t *testing.T) {
			f(&resourceFileTest, t, rc)
		},
		)
	}
}

func readUserResourceFile(t *testing.T) *collector.ResourcesContainerModel {
	inputFile := data.GetExamplesJSONPath("userResources")
	if !common.FileExist(inputFile) {
		logging.Debugf("resource file %s does not exist, nothing to test\n", inputFile)
		return nil
	}
	b, err := os.ReadFile(inputFile)
	require.Nil(t, err)
	rc, err := collector.FromJSONString(b)
	require.Nil(t, err)
	require.NotNil(t, rc)
	if len(rc.DomainList) == 0 {
		logging.Debugf("%s has no domains\n", inputFile)
		return nil
	}
	return rc
}

// ///////////////////////////////////////////////////////////////////////////////////
// subTestsRunByTestName() gets a test function to run, and run it on all the syntheticTests as subtests
func subTestsRunByTestName(t *testing.T, f testMethod) {
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	for _, test := range allSyntheticTests {
		rc, err := data.ExamplesGeneration(test.exData)
		require.Nil(t, err)
		t.Run(test.name, func(t *testing.T) {
			f(&test, t, rc)
		},
		)
	}
}

//////////////////////////////////////////
// the test methods:
//////////////////////////////////////////

func runPreprocessing(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	err := logging.Tee(path.Join(synTest.debugDir(), "runPreprocessing.log"))
	require.Nil(t, err)
	// get the config:
	config, err := configuration.ConfigFromResourcesContainer(rc, false)
	require.Nil(t, err)
	// write the config summary into a file, for debugging:
	configStr := config.GetConfigInfoStr(false)
	err = common.WriteToFile(path.Join(synTest.debugDir(), "config.txt"), configStr)
	require.Nil(t, err)
	// get the preProcess results:
	categoryToPolicy := preProcessing(config.FW.CategoriesSpecs)
	preProcessOutput := printPreProcessingSymbolicPolicy(config.FW.CategoriesSpecs, categoryToPolicy, false)
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
	abstractModelStr := strAbstractModel(abstractModel, synTest.options())
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
	// if strings.Contains(synTest.name, "Internal") {
	// 	return // todo tmp until policies in place for internal
	// }
	err := logging.Tee(path.Join(synTest.debugDir(), "runK8SSynthesis.log"))
	require.Nil(t, err)
	k8sDir := path.Join(synTest.outDir(), k8sResourcesDir)
	// create K8S resources:
	resources, err := NSXToK8sSynthesis(rc, nil, synTest.options())
	require.Nil(t, err)
	err = resources.CreateDir(synTest.outDir())
	require.Nil(t, err)
	// run netpol-analyzer, the connectivity is kept into a file, for debugging:
	err = os.MkdirAll(synTest.debugDir(), os.ModePerm)
	require.Nil(t, err)
	k8sConnectivityFile := path.Join(synTest.debugDir(), "k8s_connectivity.txt")
	k8sConnectivityFileCreated, err := k8sAnalyzer(k8sDir, k8sConnectivityFile, "txt")
	require.Nil(t, err)
	// compare k8s resources to expected results:
	if synTest.hasExpectedResults() {
		expectedOutputDir := filepath.Join(getTestsDirExpectedOut(), k8sResourcesDir, synTest.id())
		compareOrRegenerateOutputDirPerTest(t, k8sDir, expectedOutputDir, synTest.name)
	}

	if k8sConnectivityFileCreated {
		compareToNetpol(t, rc, k8sConnectivityFile)
	}
}

// the following method is work in progress - the netpol analyzer and the nsx analyser have different granularity of external IPs
func compareToNetpol(t *testing.T, rc *collector.ResourcesContainerModel, k8sConnectivityFile string) {
	// we get a file with lines in the foramt:
	// 1.2.3.0-1.2.3.255 => default/Gryffindor-Web[Pod] : UDP 1-65535
	netpolConnBytes, err := os.ReadFile(k8sConnectivityFile)
	require.Nil(t, err)
	netpolConnLines := strings.Split(string(netpolConnBytes), "\n")
	netpolConnLines = slices.DeleteFunc(netpolConnLines, func(s string) bool { return s == "" })
	netpolConnMap := map[string]string{}
	for _, line := range netpolConnLines {
		var src, dst, conn string
		spitedLine := strings.Split(line, " : ")
		conn = spitedLine[1]
		n, err := fmt.Sscanf(spitedLine[0], "%s => %s", &src, &dst)
		require.Equal(t, err, nil)
		require.Equal(t, n, 2)
		fixK8SName := func(s string) string {
			if strings.Contains(s, "[Pod]") {
				return strings.ReplaceAll(s, "[Pod]", "")
			} else {
				block, err := netset.IPBlockFromCidrOrAddress(s)
				if err != nil {
					block, err = netset.IPBlockFromIPRangeStr(s)
				}
				require.Equal(t, err, nil)
				return block.String()
			}
		}
		src = fixK8SName(src)
		dst = fixK8SName(dst)
		netpolConnMap[src+"=>"+dst] = conn
	}
	// get analyzed connectivity:
	_, connMap, _, err := analyzer.NSXConnectivityFromResourcesContainer(rc, defaultParams)
	require.Nil(t, err)
	// iterate over the connMap, check each connection:
	for src, dsts := range connMap {
		for dst, conn := range dsts {
			// todo - set the real vm namespaces:
			endpointName := func(ep topology.Endpoint) string {
				if ep.IsExternal() {
					return ep.(*topology.ExternalIP).Block.String()
				} else {
					return "default/" + toLegalK8SString(ep.Name())
				}
			}
			netpolFormat := fmt.Sprintf("%s=>%s", endpointName(src), endpointName(dst))
			netpolConn, ok := netpolConnMap[netpolFormat]
			require.Equal(t, ok, !conn.Conn.TCPUDPSet().IsEmpty())
			if ok {
				compareConns(t, conn.Conn.String(), netpolConn)
			}
		}
	}
}

func compareConns(t *testing.T, vmFormat, k8sFormat string) {
	vmFormat = strings.ReplaceAll(vmFormat, "dst-ports: ", "")
	vmFormat = strings.ReplaceAll(vmFormat, "ICMP;", "")
	vmFormat = strings.ReplaceAll(vmFormat, "ICMP,", "")
	if vmFormat == "TCP,UDP" {
		vmFormat = "All Connections"
	}
	k8sFormat = strings.ReplaceAll(k8sFormat, " 1-65535", "")
	require.Equal(t, vmFormat, k8sFormat)
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
	_, connMap, connectivity, err := analyzer.NSXConnectivityFromResourcesContainer(rc, defaultParams)
	require.Nil(t, err)
	// write to file, for debugging:
	err = common.WriteToFile(path.Join(debugDir, "vmware_connectivity.txt"), connectivity)
	require.Nil(t, err)
	connMergedMap := connMap.MergeExternalEP()
	connMergedMapStr, err := connMergedMap.GenConnectivityOutput(defaultParams)
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "vmware_merged_connectivity.txt"), connMergedMapStr)
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

	// get the config from generated_rc:
	config, err := configuration.ConfigFromResourcesContainer(rc, false)
	require.Nil(t, err)
	// write the config summary into a file, for debugging:
	configStr := config.GetConfigInfoStr(false)
	err = common.WriteToFile(path.Join(synTest.debugDir(), "generated_nsx_config.txt"), configStr)
	require.Nil(t, err)

	// run the analyzer on the new NSX config (from abstract), and store in text file
	_, analyzedMap, analyzed, err := analyzer.NSXConnectivityFromResourcesContainer(rc, defaultParams)
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_connectivity.txt"), analyzed)
	require.Nil(t, err)
	analyzedMergedMap := analyzedMap.MergeExternalEP()
	analyzedMergedMapStr, err := analyzedMergedMap.GenConnectivityOutput(defaultParams)
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_merged_connectivity.txt"), analyzedMergedMapStr)
	require.Nil(t, err)
	// the validation of the abstract model conversion is here:
	// validate connectivity analysis is the same for the new (from abstract) and original NSX configs
	require.Equal(t, connMergedMapStr, analyzedMergedMapStr,
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
