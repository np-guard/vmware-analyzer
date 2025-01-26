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
	allowOnlyFromCategory collector.DfwCategory // category to start the "allow-only" conversion from
	noHint                bool                  // run also with no hint
}

var groupsByVmsTests = []synthesisTest{
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
		name:                  "ExampleHogwarts",
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
	for i := range groupsByVmsTests {
		test := &groupsByVmsTests[i]
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
	outDir := path.Join("out", synTest.name, "k8s_resources")
	debugDir := path.Join("out", synTest.name, "debug_resources")
	abstractModel, err := NSXToK8sSynthesis(rc, outDir, hintsParm, synTest.allowOnlyFromCategory)
	require.Nil(t, err)
	addDebugFiles(t, rc, abstractModel, debugDir, synTest.allowOnlyFromCategory == 0)
	expectedOutputFileName := filepath.Join(getTestsDirOut(), synTest.name+suffix)
	actualOutput := strAllowOnlyPolicy(abstractModel.policy[0])
	fmt.Println(actualOutput)
	compareOrRegenerateOutputPerTest(t, mode, actualOutput, expectedOutputFileName, synTest.name)
}

// todo - remove the allowOnly flag after supporting deny
func addDebugFiles(t *testing.T, rc *collector.ResourcesContainerModel, abstractModel *AbstractModelSyn, outDir string, allowOnly bool) {
	connectivity := map[string]string{}
	var err error
	// generate connectivity analysis output from the original NSX resources
	for _, format := range []string{"txt", "dot"} {
		params := common.OutputParameters{
			Format: format,
		}
		connectivity[format], err = model.NSXConnectivityFromResourcesContainer(rc, params)
		require.Nil(t, err)
		err = common.WriteToFile(path.Join(outDir, "vmware_connectivity."+format), connectivity[format])
		require.Nil(t, err)
	}
	// write the abstract model rules into a file
	actualOutput := strAllowOnlyPolicy(abstractModel.policy[0])
	err = common.WriteToFile(path.Join(outDir, "abstract_model.txt"), actualOutput)
	require.Nil(t, err)

	// store the original NSX resources in JSON
	jsonOut, err := rc.ToJSONString()
	if err != nil {
		t.Errorf("failed in converting to json: error = %v", err)
		return
	}
	err = common.WriteToFile(path.Join(outDir, "nsx_resources.json"), jsonOut)
	if err != nil {
		t.Errorf("failed in write to file: error = %v", err)
		return
	}

	// convert the abstract model to a new equiv NSX config
	policies, groups := toNSXPolicies(rc, abstractModel)
	rc.DomainList[0].Resources.SecurityPolicyList = policies                                       // override policies
	rc.DomainList[0].Resources.GroupList = append(rc.DomainList[0].Resources.GroupList, groups...) // update groups
	jsonOut, err = rc.ToJSONString()
	if err != nil {
		t.Errorf("failed in converting to json: error = %v", err)
		return
	}
	// store the *new* (from abstract model) NSX JSON config in a file
	err = common.WriteToFile(path.Join(outDir, "generated_nsx_resources.json"), jsonOut)
	if err != nil {
		t.Errorf("failed in write to file: error = %v", err)
		return
	}

	params := common.OutputParameters{
		Format: "txt",
	}
	// run the analyzer on the new NSX config (from abstract), and store in text file
	analyzed, err := model.NSXConnectivityFromResourcesContainer(rc, params)
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(outDir, "generated_nsx_connectivity.txt"), analyzed)
	require.Nil(t, err)

	// the validation of the abstract model conversion is here:
	// validate connectivity analysis is the same for the new (from abstract) and original NSX configs
	if allowOnly {
		// todo - remove the if after supporting deny
		require.Equal(t, connectivity["txt"], analyzed,
			fmt.Sprintf("nsx and vmware connectivities of test %v are not equal", t.Name()))
	}
}

// to be run only on "live nsx" mode
// no expected output is tested
// only generates
// (1) converted config into k8s network policies
// (2) equiv config in NSX with allow-only DFW rules, as derived from the abstract model
// and validates that connectivity of orign and new NSX configs are the same
func TestCollectAndConvertToAbstract(t *testing.T) {
	server := collector.NewServerData(os.Getenv("NSX_HOST"), os.Getenv("NSX_USER"), os.Getenv("NSX_PASSWORD"))
	if (server == collector.ServerData{}) {
		fmt.Println(common.ErrNoHostArg)
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
	outDir := path.Join("out", "from_collection", "k8s_resources")
	debugDir := path.Join("out", "from_collection", "debug_resources")
	abstractModel, err := NSXToK8sSynthesis(rc, outDir,
		&symbolicexpr.Hints{GroupsDisjoint: [][]string{}}, 0)
	require.Nil(t, err)
	// print the conntent of the abstract model
	fmt.Println(strAllowOnlyPolicy(abstractModel.policy[0]))

	addDebugFiles(t, rc, abstractModel, debugDir, false)
	require.Nil(t, err)
}

// this function runs on generated examples
// calls to addDebugFiles  - see comments there
func TestConvertToAbsract(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for _, test := range groupsByVmsTests {
		t.Run(test.name, func(t *testing.T) {
			// to generate output comment the following line and uncomment the one after
			test.runConvertToAbstract(t, OutputComparison)
			//nolint:gocritic // uncomment for generating output
			//test.runConvertToAbstract(t, OutputGeneration)
		},
		)
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
