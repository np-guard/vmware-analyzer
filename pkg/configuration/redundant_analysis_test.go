package configuration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/data"
)

// Test redundant analysis:
// In the tests below the basicExampleTopology contains only two VMs: A and B.
// Each rulesTest contains list of DFW rules, and expected redundant rules per each DFW config.
// the test validates that returned redundant rules are as expected.

var basicExampleTopology = data.Example{
	VMs: []string{"A", "B"},
	GroupsByVMs: map[string][]string{
		"frontend": {"A"},
		"backend":  {"B"},
		"system":   {},
	},
}

type rulesTest struct {
	testName     string
	envRulesList []data.Rule
	appRulesList []data.Rule
	expectedRes  [][]string // "potential redundant rule ID", "dfw_category", "direction", "possible shoadowing rules IDs"
}

func services(s ...string) []string {
	res := []string{}
	for _, str := range s {
		switch str {
		case common.AnyStr:
			return []string{common.AnyStr}
		default:
			res = append(res, fmt.Sprintf("/infra/services/%s", str))
		}
	}
	return res
}

var rulesTests = []*rulesTest{
	{
		// small example - no redundant rules
		testName: "no_redundant_rules",
		appRulesList: []data.Rule{
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
			{Name: "denyRule", Source: common.AnyStr, Dest: common.AnyStr, Services: services(common.AnyStr), Action: data.Drop},
		},
		expectedRes: [][]string{},
	},
	{
		// small example - one redundant (duplicated)
		testName: "one_duplicated_rule",
		appRulesList: []data.Rule{
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},              // 1
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},              // 2
			{Name: "denyRule", Source: common.AnyStr, Dest: common.AnyStr, Services: services(common.AnyStr), Action: data.Drop}, // 3
		},
		expectedRes: [][]string{
			{"2", "Application", "IN_OUT", "[1]"}, // rule 2 is redundant, covered by rule 1
		},
	},
	{
		// small example - one redundant (only one direction)
		testName: "one_duplicated_rule_one_direction_only",
		appRulesList: []data.Rule{
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow, Direction: "IN"},
			{Name: "denyRule", Source: common.AnyStr, Dest: common.AnyStr, Services: services(common.AnyStr), Action: data.Drop},
		},
		expectedRes: [][]string{
			{"2", "Application", "IN", "[1]"}, // rule 2 is redundant, covered by rule 1
		},
	},
	{
		// small example - one redundant (covered by 2 rules )
		testName: "one_redundant_covered_by_2_rules",
		appRulesList: []data.Rule{
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("HTTP"), Action: data.Allow},
			{Name: "allowRule", Source: "backend", Dest: "system", Services: services("HTTPS"), Action: data.Allow},
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB", "HTTP"), Action: data.Allow},
			{Name: "denyRule", Source: common.AnyStr, Dest: common.AnyStr, Services: services(common.AnyStr), Action: data.Drop},
		},
		expectedRes: [][]string{
			{"4", "Application", "IN_OUT", "[1 2]"}, // rule 3 is redundant, covered by rules 1,2
		},
	},
	{
		// small example - one redundant (contained in higher prio rule) (different action)
		testName: "one_redundant_rule_containment_in_higher_prio_rule",
		appRulesList: []data.Rule{
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services(common.AnyStr), Action: data.Drop},       // 1
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},              // 2
			{Name: "denyRule", Source: common.AnyStr, Dest: common.AnyStr, Services: services(common.AnyStr), Action: data.Drop}, // 3
		},
		expectedRes: [][]string{
			{"2", "Application", "IN_OUT", "[1]"}, // rule 2 is redundant, covered by rule 1
		},
	},
}

func (r *rulesTest) runTest(t *testing.T) {
	// build example from input
	example := basicExampleTopology.CopyTopology()
	example.Name = r.testName
	example.InitEmptyEnvAppCategories()
	for i := range r.envRulesList {
		err := example.AddRuleToExampleInCategory(collector.EnvironmentStr, &r.envRulesList[i])
		require.Nil(t, err)
	}
	for i := range r.appRulesList {
		err := example.AddRuleToExampleInCategory(collector.ApplicationStr, &r.appRulesList[i])
		require.Nil(t, err)
	}

	// get ResourcesContainerModel from Example object
	var override bool
	//nolint: gocritic //keep this commented out code for test updates
	// override = true // use when modifying the tests below..
	rc, err := data.ExamplesGeneration(example, override)
	require.Nil(t, err)

	config, err := ConfigFromResourcesContainer(rc, common.OutputParameters{})
	require.Nil(t, err)

	// compare redundant rules analysis
	_, reportLines := config.FW.RedundantRulesAnalysis(config.VMs, false)
	require.Equal(t, r.expectedRes, reportLines)
}

func TestRedundantRulesAnalysis(t *testing.T) {
	for i := range rulesTests {
		rulesTests[i].runTest(t)
	}
}

/*
// todo: move these functions to another package

func newTCPWithPort(p int64) *netset.TransportSet {
	return netset.NewTCPTransport(1, 65535, p, p)
}

//nolint:unparam //  `p1` always receives `1` only currently..needs both params
func newTCPWIthPortRange(p1, p2 int64) *netset.TransportSet {
	return netset.NewTCPTransport(1, 65535, p1, p2)
}
*/
