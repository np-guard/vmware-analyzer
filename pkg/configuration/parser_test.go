package configuration

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/internal/projectpath"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

type groupPathParserTest struct {
	path              string
	expectedNumVMs    int
	expectedNumBlocks int
	expectedNumGroups int
}

// (1) for each group example, add support in examples-generator, and validate analysis support
// (2) next step - validate synthesis support

// validate dfw.RuleEndpoints object returned from input group path by parser.getEndpointsFromGroupsPaths()
func (g *groupPathParserTest) runTest(t *testing.T, parser *nsxConfigParser) {
	fmt.Printf("test for path: %s\n", g.path)
	ruleEndpoints := parser.getEndpointsFromGroupsPaths([]string{g.path}, false)
	fmt.Printf("%s\n\n", ruleEndpoints.String())
	require.Equal(t, g.expectedNumVMs, len(ruleEndpoints.VMs))
	require.Equal(t, g.expectedNumBlocks, len(ruleEndpoints.Blocks))
	require.Equal(t, g.expectedNumGroups, len(ruleEndpoints.Groups))

	// TODO: add injection of single DFW Rule per tested group, and test analysis res as well.
}

// test getEndpointsFromGroupsPaths() over input paths
var testPaths = []*groupPathParserTest{
	{

		path:              "/infra/domains/default/groups/ex1-ip-addr-only-external",
		expectedNumBlocks: 1,
		expectedNumGroups: 1,
		/*
			test for path: /infra/domains/default/groups/ex1-ip-addr-only-external
			VMs:
			Groups: ex1-ip-addr-only-external
			Blocks:
			 block: 8.8.8.8 , origIP: 8.8.8.8/32
			external range: 8.8.8.8
			vms:
			ExternalIPs: 8.8.8.8
			Segments:
			SegmentsVMs:
		*/
	},
	{

		path:              "8.8.8.8/32",
		expectedNumBlocks: 1,
		/*
			test for path: 8.8.8.8/32
			VMs:
			Groups:
			Blocks:
			 block: 8.8.8.8 , origIP: 8.8.8.8/32
			external range: 8.8.8.8
			vms:
			ExternalIPs: 8.8.8.8
			Segments:
			SegmentsVMs:
		*/
	},
	{
		path:              "/infra/domains/default/groups/ex2-ip-addr-only-internal",
		expectedNumVMs:    1,
		expectedNumBlocks: 1,
		expectedNumGroups: 1,
		/*
			test for path: /infra/domains/default/groups/ex2-ip-addr-only-internal
			VMs: New-VM-4
			Groups: ex2-ip-addr-only-internal
			Blocks:
			 block: 192.168.0.2 , origIP: 192.168.0.2/32
			external range:
			vms: New-VM-4
			ExternalIPs:
			Segments:
			SegmentsVMs:
		*/
	},
	{
		path: "/infra/domains/default/groups/foo-app", // this group is based on expr: vm.tag == "foo-app"
		/*
			test for path: /infra/domains/default/groups/foo-app
			VMs: New-VM-3,New-VM-4
			Groups: foo-app
			Blocks:
		*/
		expectedNumVMs:    2,
		expectedNumGroups: 1,
	},
	{
		// ex3 is composed of multiple defs: (1) sub group (foo-app) , (2) segment (3) VM
		// (1) can be inferred from pathExpr
		// (2) can be inferred from pathExpr
		// (3) can be inferred from ExternalIDExpression
		path: "/infra/domains/default/groups/ex3-generic-members-based-def",
		/*
			test for path: /infra/domains/default/groups/ex3-generic-members-based-def
			VMs: New-VM-1,New-VM-2,New Virtual Machine,New-VM-3,New-VM-4,dev-dal10-r1
			Groups: ex3-generic-members-based-def
			Blocks:
		*/
		expectedNumGroups: 1,
		expectedNumVMs:    6,
	},
	{
		// ex4 was defined via the vif member option
		// in the json expr, it's a ExternalIDExpression, pointing to the id of the vif member selected,
		// of VirtualNetworkInterface resource type
		path:              "/infra/domains/default/groups/ex4-generic-vif-member-def",
		expectedNumGroups: 1,
		expectedNumVMs:    1,
		/*
			test for path: /infra/domains/default/groups/ex4-generic-vif-member-def
			VMs: New-VM-1
			Groups: ex4-generic-vif-member-def
			Blocks:

		*/
	},
	{},
}

// test parsed groups members and interpretation done by RuleEndpoints by function getEndpointsFromGroupsPaths()
func TestParser(t *testing.T) {
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	currentDir, _ := os.Getwd()
	err := logging.Tee(path.Join(filepath.Join(currentDir, "out"), "log.txt"))
	require.Nil(t, err)
	parser, err := newNSXConfigParserFromFile(projectpath.Root + "/examples/simple19.json")
	if err != nil {
		// do not fail the test if input file is missing on tested env
		return
	}
	err = parser.runParser()
	require.Nil(t, err)

	for _, testInstance := range testPaths {
		testInstance.runTest(t, parser)
	}

	fmt.Println("done")
}

/*


func TestParser(t *testing.T) {
	parser, err := NewNSXConfigParserFromFile("")
	if err != nil {
		t.Fatal(err.Error())
	}

	err = parser.RunParser()
	if err != nil {
		t.Fatal(err.Error())
	}
	config := parser.GetConfig()
	fmt.Println(config.getConfigInfoStr())

	config.ComputeConnectivity()
	fmt.Println("analyzed Connectivity")
	fmt.Println(config.Connectivity.String())
	fmt.Println("done")
}*/
