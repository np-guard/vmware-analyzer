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

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/data"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/nsx"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/resources"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

const (
	expectedOutput = "tests_expected_output"
	actualOutput   = "tests_actual_output"
)

type synthesisTest struct {
	name            string
	exData          *data.Example
	synthesizeAdmin bool
	noHint          bool // run also with no hint
	filter          []string
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
	if synTest.filter != nil {
		id += "_Filtered"
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
func (synTest *synthesisTest) options() *config.SynthesisOptions {
	res := &config.SynthesisOptions{
		Hints:           synTest.hints(),
		SynthesizeAdmin: synTest.synthesizeAdmin,
		CreateDNSPolicy: true,
		FilterVMs:       synTest.filter,
		// default enum flags values:
		//EndpointsMapping: common.EndpointsBoth,
		//SegmentsMapping:  common.SegmentsToUDNs,
	}
	res.EndpointsMapping.SetDefault()
	res.SegmentsMapping.SetDefault()
	return res
}
func (synTest *synthesisTest) outputParams() common.OutputParameters {
	return common.OutputParameters{Format: "txt", VMs: synTest.filter}
}

var groupsByVmsTests = []synthesisTest{
	{
		name:            "Example1c",
		exData:          data.Example1c,
		synthesizeAdmin: false,
		noHint:          true,
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
		name:            "ExampleHogwartsFiltered",
		exData:          data.ExampleHogwarts,
		synthesizeAdmin: false,
		noHint:          false,
		filter:          []string{data.SlyWeb, data.GryWeb, data.HufWeb, data.Dum1, data.Dum2},
	},
	{
		name:            "ExampleHogwartsSimplerNonSymInOutAdmin",
		exData:          data.ExampleHogwartsSimplerNonSymInOut,
		synthesizeAdmin: true,
		noHint:          false,
	},
	{
		name:            "ExampleHogwartsExcludeSimple",
		exData:          data.ExampleHogwartsExcludeSimple,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleAppWithGroupsAndSegments",
		exData:          data.ExampleAppWithGroupsAndSegments,
		synthesizeAdmin: false,
		noHint:          false,
	},
}

var vmsByIpsTests = []synthesisTest{
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
		name:            "Example1dExternalWithSegmentsFiltered",
		exData:          data.Example1dExternalWithSegments,
		synthesizeAdmin: false,
		noHint:          true,
		filter:          []string{"A", "B"},
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
		name:            "ExampleInternalWithInterDenyAllowMixedSegments",
		exData:          data.ExampleInternalWithInterDenyAllowMixedSegments,
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
		name:            "ExampleExternalWithTautology",
		exData:          data.ExampleExternalWithTautology,
		noHint:          false,
		synthesizeAdmin: false,
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
	{
		name:   "ExampleExprOrCondsExclude",
		exData: data.ExampleExprOrCondsExclude,
		noHint: false,
	},
	{
		name:   "ExampleExprAndCondsExclude",
		exData: data.ExampleExprAndCondsExclude,
		noHint: false,
	},
}

var groupsOfNonVMsTests = []synthesisTest{
	{
		name:            "ExampleGroup3",
		exData:          data.ExampleGroup3,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleGroup1",
		exData:          data.ExampleGroup1,
		synthesizeAdmin: false,
		noHint:          false,
	},
	{
		name:            "ExampleGroup2",
		exData:          data.ExampleGroup2,
		synthesizeAdmin: false,
		noHint:          false,
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

var allSyntheticTests = append(groupsByVmsTests, append(groupsByExprTests,
	append(vmsByIpsTests, groupsOfNonVMsTests...)...)...)
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
		rc, err := data.ExamplesGeneration(test.exData, false)
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
	// get the nsxConfig:
	nsxConfig, err := configuration.ConfigFromResourcesContainer(rc, synTest.outputParams())
	require.Nil(t, err)
	// write the config summary into a file, for debugging:
	configStr := nsxConfig.GetConfigInfoStr(false)
	err = common.WriteToFile(path.Join(synTest.debugDir(), "config.txt"), configStr)
	require.Nil(t, err)
	// get the preProcess results:
	categoryToPolicy := model.PreProcessing(nsxConfig, nsxConfig.FW.CategoriesSpecs)
	preProcessOutput := model.PrintPreProcessingSymbolicPolicy(nsxConfig.FW.CategoriesSpecs, categoryToPolicy, false)
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
	abstractModel, err := model.NSXConfigToAbstractModel(rc, nil, synTest.options())
	require.Nil(t, err)
	abstractModelStr := model.StrAbstractModel(abstractModel, synTest.options())
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
	k8sDir := path.Join(synTest.outDir(), resources.K8sResourcesDir)
	// create K8S allResources:
	allResources, err := ocpvirt.NSXToK8sSynthesis(rc, nil, synTest.options())
	require.Nil(t, err)
	err = allResources.WriteResourcesToDir(synTest.outDir())
	require.Nil(t, err)
	// compare k8s resources to expected results:
	if synTest.hasExpectedResults() {
		expectedOutputDir := filepath.Join(getTestsDirExpectedOut(), resources.K8sResourcesDir, synTest.id())
		compareOrRegenerateOutputDirPerTest(t, k8sDir, expectedOutputDir, synTest.name)
	}
	// run netpol-analyzer, the connectivity is kept into a file, for debugging:
	err = os.MkdirAll(synTest.debugDir(), os.ModePerm)
	require.Nil(t, err)
	k8sConnectivityFile := path.Join(synTest.debugDir(), "k8s_connectivity.txt")
	k8sConnectivityFileCreated, err := utils.K8sAnalyzer(k8sDir, k8sConnectivityFile, "txt")
	require.Nil(t, err)

	if k8sConnectivityFileCreated && !allResources.NotFullySupported {
		compareToNetpol(synTest, t, rc, k8sConnectivityFile)
	} else {
		logging.Debugf("test %s: skip comparing netpol analyzer connectivity with vmware connectivity", synTest.name)
	}
}

func compareToNetpol(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel, k8sConnectivityFile string) {
	// get analyzed connectivity:
	nsxConfig, connMap, _, err := analyzer.NSXConnectivityFromResourcesContainer(rc, synTest.outputParams())
	require.Nil(t, err)
	noIcmpGroupedExternalToAllMap := removeICMP(connMap)
	debugDir := synTest.debugDir()
	noICMPGroupedMapStr, err := noIcmpGroupedExternalToAllMap.GenConnectivityOutput(synTest.outputParams())
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "vmware_no_icmp_grouped_connectivity.txt"), noICMPGroupedMapStr)
	require.Nil(t, err)

	k8sConnMap := readK8SConnFile(t, k8sConnectivityFile)
	k8sGroupedNoNoInternalAddressesMap := removeInternalAddresses(k8sConnMap, nsxConfig.Topology.AllExternalIPBlock)
	k8sGroupedMapStr, err := k8sGroupedNoNoInternalAddressesMap.GenConnectivityOutput(synTest.outputParams())
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "k8s_grouped_connectivity.txt"), k8sGroupedMapStr)
	require.Nil(t, err)
	require.Equal(t, noICMPGroupedMapStr, k8sGroupedMapStr,
		fmt.Sprintf("k8s and vmware connectivities of test %v are not equal", t.Name()))
}

// adjust connectivity map to be later compared to netpol analyzer map:
// 1. remove ICMP
func removeICMP(connMap connectivity.ConnMap) connectivity.ConnMap {
	noIcmpMap := connectivity.ConnMap{}
	for src, srcMap := range connMap {
		for dst, conn := range srcMap {
			noIcmpConn := netset.NewTCPUDPTransportFromTCPUDPSet(conn.Conn.TCPUDPSet())
			if !noIcmpConn.IsEmpty() {
				noIcmpMap.Add(src, dst, connectivity.NewDetailedConnection(noIcmpConn, nil))
			}
		}
	}
	noIcmpGroupedMap := noIcmpMap.GroupExternalEP()
	adjustEP := func(ep topology.Endpoint) topology.Endpoint {
		if !ep.IsExternal() {
			return topology.NewVM(utils.ToLegalK8SString(ep.Name()), ep.ID())
		}
		return ep
	}

	noIcmpGroupedLegalMap := connectivity.ConnMap{}
	for src, srcMap := range noIcmpGroupedMap {
		for dst, conn := range srcMap {
			noIcmpGroupedLegalMap.Add(adjustEP(src), adjustEP(dst), conn)
		}
	}
	return noIcmpGroupedLegalMap
}

// replace 0.0.0.0/0 with all external
func removeInternalAddresses(connMap connectivity.ConnMap, allExternal *netset.IPBlock) connectivity.ConnMap {
	groupedMap := connMap.GroupExternalEP()
	allExternalEP := topology.NewExternalIP(allExternal)
	adjustEP := func(ep topology.Endpoint) topology.Endpoint {
		if ep.IsExternal() && ep.(*topology.ExternalIP).Block.Equal(netset.GetCidrAll()) {
			return allExternalEP
		}
		return ep
	}

	GroupedExternalToAllMap := connectivity.ConnMap{}
	for src, srcMap := range groupedMap {
		for dst, conn := range srcMap {
			GroupedExternalToAllMap.Add(adjustEP(src), adjustEP(dst), conn)
		}
	}
	return GroupedExternalToAllMap
}

func readK8SConnFile(t *testing.T, k8sConnectivityFile string) connectivity.ConnMap {
	// we get a file with lines in the foramt:
	// 1.2.3.0-1.2.3.255 => default/Gryffindor-Web[Pod] : UDP 1-65535
	netpolConnBytes, err := os.ReadFile(k8sConnectivityFile)
	require.Nil(t, err)
	netpolConnLines := strings.Split(string(netpolConnBytes), "\n")
	netpolConnLines = slices.DeleteFunc(netpolConnLines, func(s string) bool { return s == "" })
	k8sConnMap := connectivity.ConnMap{}
	for _, line := range netpolConnLines {
		var src, dst, connStr string
		spitedLine := strings.Split(line, " : ")
		connStr = spitedLine[1]
		n, err := fmt.Sscanf(spitedLine[0], "%s => %s", &src, &dst)
		require.Equal(t, err, nil)
		require.Equal(t, n, 2)
		nameToEP := func(s string) topology.Endpoint {
			if strings.Contains(s, "[Pod]") {
				s = strings.ReplaceAll(s, "[Pod]", "")
				nameAndSpace := strings.Split(s, "/")
				return topology.NewVM(nameAndSpace[1], nameAndSpace[1])
			} else {
				block, err := netset.IPBlockFromCidrOrAddress(s)
				if err != nil {
					block, err = netset.IPBlockFromIPRangeStr(s)
				}
				require.Equal(t, err, nil)
				return topology.NewExternalIP(block)
			}
		}
		strToConn := func(str string) *connectivity.DetailedConnection {
			res := connectivity.NewEmptyDetailedConnection()
			for _, e := range strings.Split(str, ",") {
				if e == "All Connections" {
					return connectivity.NewDetailedConnection(netset.AllOrNothingTransport(true, false), nil)
				}
				var protocol netp.ProtocolString
				var minPort, maxPort int64
				e = strings.ReplaceAll(e, "-", " ")
				n, err := fmt.Sscanf(e, "%s %d %d", &protocol, &minPort, &maxPort)
				if n == 2 {
					maxPort = minPort
				} else {
					require.Equal(t, err, nil)
				}
				res.Conn = res.Conn.Union(netset.NewTCPorUDPTransport(protocol, netp.AllPorts().Start(), netp.AllPorts().End(), minPort, maxPort))
			}
			return res
		}
		srcEP := nameToEP(src)
		dstEP := nameToEP(dst)
		k8sConnMap.Add(srcEP, dstEP, strToConn(connStr))
	}
	return k8sConnMap
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
	_, connMap, connectivityRes, err := analyzer.NSXConnectivityFromResourcesContainer(rc, synTest.outputParams())
	require.Nil(t, err)
	// write to file, for debugging:
	err = common.WriteToFile(path.Join(debugDir, "vmware_connectivity.txt"), connectivityRes)
	require.Nil(t, err)
	connGroupedMap := connMap.GroupExternalEP()
	connGroupedMapStr, err := connGroupedMap.GenConnectivityOutput(synTest.outputParams())
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "vmware_grouped_connectivity.txt"), connGroupedMapStr)
	require.Nil(t, err)

	// create abstract model convert it to a new equiv NSX resources:
	abstractModel, err := model.NSXConfigToAbstractModel(rc, nil, synTest.options())
	require.Nil(t, err)
	policies, groups := nsx.AbstractToNSXPolicies(rc, abstractModel)
	// merge the generate resources into the orig resources. store in into JSON config in a file, for debugging::
	rc.DomainList[0].Resources.SecurityPolicyList = policies                                       // override policies
	rc.DomainList[0].Resources.GroupList = append(rc.DomainList[0].Resources.GroupList, groups...) // update groups
	jsonOut, err = rc.ToJSONString()
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_resources.json"), jsonOut)
	require.Nil(t, err)

	// get the nsxConfig from generated_rc:
	nsxConfig, err := configuration.ConfigFromResourcesContainer(rc, synTest.outputParams())
	require.Nil(t, err)
	// write the config summary into a file, for debugging:
	configStr := nsxConfig.GetConfigInfoStr(false)
	err = common.WriteToFile(path.Join(synTest.debugDir(), "generated_nsx_config.txt"), configStr)
	require.Nil(t, err)

	// run the analyzer on the new NSX config (from abstract), and store in text file
	_, analyzedMap, analyzed, err := analyzer.NSXConnectivityFromResourcesContainer(rc, synTest.outputParams())
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_connectivity.txt"), analyzed)
	require.Nil(t, err)
	analyzedGroupedMap := analyzedMap.GroupExternalEP()
	analyzedGroupedMapStr, err := analyzedGroupedMap.GenConnectivityOutput(synTest.outputParams())
	require.Nil(t, err)
	err = common.WriteToFile(path.Join(debugDir, "generated_nsx_grouped_connectivity.txt"), analyzedGroupedMapStr)
	require.Nil(t, err)
	// the validation of the abstract model conversion is here:
	// validate connectivity analysis is the same for the new (from abstract) and original NSX configs
	require.Equal(t, connGroupedMapStr, analyzedGroupedMapStr,
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
var runTestMode = OutputComparison

func compareOrRegenerateOutputDirPerTest(t *testing.T, actualDir, expectedDir, testName string) {
	actualFiles, err := os.ReadDir(actualDir)
	require.Nil(t, err)
	// if the --update flag is on (then generate/ override the expected output file with the actualOutput)
	if *common.Update {
		runTestMode = OutputGeneration
	}
	switch runTestMode {
	case OutputComparison:
		expectedFiles, err := os.ReadDir(expectedDir)
		require.Nil(t, err)
		require.Equal(t, len(expectedFiles), len(actualFiles),
			fmt.Sprintf("number of output files of test %v not as expected", testName))
		for _, file := range actualFiles {
			expectedOutput, err := os.ReadFile(filepath.Join(expectedDir, file.Name()))
			require.Nil(t, err)
			actualOutput, err := os.ReadFile(filepath.Join(actualDir, file.Name()))
			require.Nil(t, err)
			require.Equal(t, common.CleanStr(string(actualOutput)), common.CleanStr(string(expectedOutput)),
				fmt.Sprintf("output file %s of test %v not as expected", file.Name(), testName))
		}
	case OutputGeneration:
		err := os.RemoveAll(expectedDir)
		require.Nil(t, err)
		err = os.CopyFS(expectedDir, os.DirFS(actualDir))
		require.Nil(t, err)
	}
}

func compareOrRegenerateOutputPerTest(t *testing.T, actualOutput, expectedOutputFileName, testName string) {
	switch runTestMode {
	case OutputComparison:
		expectedOutput, err := os.ReadFile(expectedOutputFileName)
		require.Nil(t, err)
		expectedOutputStr := string(expectedOutput)
		require.Equal(t, common.CleanStr(actualOutput), common.CleanStr(expectedOutputStr),
			fmt.Sprintf("output of test %v not as expected", testName))
	case OutputGeneration:
		err := common.WriteToFile(expectedOutputFileName, actualOutput)
		require.Nil(t, err)
	}
}
