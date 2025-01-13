package model

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

// Test connectivity analysis explanation:
// In the tests below the basicExampleTopology contains only two VMs: A and B.
// Each rulesTest contains list of DFW rules, and expected explanations per certain connection objects.
// the test validates that isAllow and ingress/egress rules explanations are as expected.

var basicExampleTopology = data.Example{
	VMs: []string{"A", "B"},
	Groups: map[string][]string{
		"frontend": {"A"},
		"backend":  {"B"},
	},
}

type expectedExplanation struct {
	conn         *netset.TransportSet
	isAllowed    bool
	ingressRules []string
	egressRules  []string
}

type rulesTest struct {
	testName     string
	envRulesList []data.Rule
	appRulesList []data.Rule
	expectedRes  []expectedExplanation
}

func services(s ...string) []string {
	res := []string{}
	for _, str := range s {
		switch str {
		case anyStr:
			return []string{anyStr}
		default:
			res = append(res, fmt.Sprintf("/infra/services/%s", str))
		}
	}
	return res
}

const (
	smbPort   = 445
	httpPort  = 80
	httpsPort = 443
)

//nolint:lll // long lines for test spec only
var rulesTests = []*rulesTest{
	{
		// simple test: one allow rule with default deny rule
		testName: "one_allow_and_default_deny",
		appRulesList: []data.Rule{
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
			{Name: "denyRule", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"allowRule"},
				egressRules:  []string{"allowRule"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    false,
				ingressRules: []string{"denyRule"},
				egressRules:  []string{"denyRule"},
			},
			{
				conn:         newTCPWIthPortRange(1, httpPort),
				isAllowed:    false,
				ingressRules: []string{"denyRule"},
				egressRules:  []string{"denyRule"},
			},
		},
	},
	{
		testName: "one_deny_and_default_allow",
		appRulesList: []data.Rule{
			{Name: "denyRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Drop},
			{Name: "allowRule", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Allow},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    false,
				ingressRules: []string{"denyRule"},
				egressRules:  []string{"denyRule"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    true,
				ingressRules: []string{"allowRule"},
				egressRules:  []string{"allowRule"},
			},
			{
				conn:         newTCPWIthPortRange(1, httpPort),
				isAllowed:    true,
				ingressRules: []string{"allowRule"},
				egressRules:  []string{"allowRule"},
			},
		},
	},
	{
		testName: "two_allow_rules",
		appRulesList: []data.Rule{
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
			{Name: "allowRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Allow},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"allowRule"},
				egressRules:  []string{"allowRule"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    true,
				ingressRules: []string{"allowRuleDefault"},
				egressRules:  []string{"allowRuleDefault"},
			},
			{
				conn:         newTCPWIthPortRange(1, httpPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleDefault"},
				egressRules:  []string{"allowRuleDefault"},
			},
		},
	},

	{
		testName: "default_allow_first",
		appRulesList: []data.Rule{
			{Name: "allowRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Allow},
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleDefault"},
				egressRules:  []string{"allowRuleDefault"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    true,
				ingressRules: []string{"allowRuleDefault"},
				egressRules:  []string{"allowRuleDefault"},
			},
			{
				conn:         newTCPWIthPortRange(1, httpPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleDefault"},
				egressRules:  []string{"allowRuleDefault"},
			},
		},
	},

	{
		testName: "default_deny_first",
		appRulesList: []data.Rule{
			{Name: "denyRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
			{Name: "allowRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Allow},
			{Name: "allowRule", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
			{
				conn:         newTCPWIthPortRange(1, httpPort),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
		},
	},

	{
		testName: "two_allow_default_deny",
		appRulesList: []data.Rule{
			{Name: "allowRuleHTTP", Source: "frontend", Dest: "backend", Services: services("HTTP"), Action: data.Allow},
			{Name: "allowRuleSMB", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
			{Name: "denyRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleSMB"},
				egressRules:  []string{"allowRuleSMB"},
			},
			{
				conn:         newTCPWithPort(httpPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleHTTP"},
				egressRules:  []string{"allowRuleHTTP"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
			{
				conn:         newTCPWIthPortRange(1, 79),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
		},
	},

	{
		testName: "one_allow_rule_multiple_services",
		appRulesList: []data.Rule{
			{Name: "allowRuleHTTP/SMB", Source: "frontend", Dest: "backend", Services: services("HTTP", "SMB"), Action: data.Allow},
			{Name: "allowRuleSMB", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
			{Name: "denyRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleHTTP/SMB"},
				egressRules:  []string{"allowRuleHTTP/SMB"},
			},
			{
				conn:         newTCPWithPort(httpPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleHTTP/SMB"},
				egressRules:  []string{"allowRuleHTTP/SMB"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
			{
				conn:         newTCPWIthPortRange(1, 79),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
		},
	},

	{
		testName: "one_allow_rule_multiple_services_partial_redundant",
		appRulesList: []data.Rule{
			{Name: "allowRuleSMB", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow},
			{Name: "allowRuleHTTP/SMB", Source: "frontend", Dest: "backend", Services: services("HTTP", "SMB"), Action: data.Allow},
			{Name: "denyRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleSMB"},
				egressRules:  []string{"allowRuleSMB"},
			},
			{
				conn:         newTCPWithPort(httpPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleHTTP/SMB"},
				egressRules:  []string{"allowRuleHTTP/SMB"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
			{
				conn:         newTCPWIthPortRange(1, 79),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
		},
	},
	// tests  with direction in/out only
	{
		testName: "direction_in_separate_rule_res_is_drop",
		appRulesList: []data.Rule{
			{Name: "allowRuleSMBIngressOnly", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow, Direction: string(nsx.RuleDirectionIN)},
			{Name: "denyRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    false,
				ingressRules: []string{"allowRuleSMBIngressOnly"},
				egressRules:  []string{"denyRuleDefault"},
			},
		},
	},
	{
		testName: "direction_in_separate_rule_res_is_allow",
		appRulesList: []data.Rule{
			{Name: "allowRuleSMBIngressOnly", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow, Direction: string(nsx.RuleDirectionIN)},
			{Name: "allowRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Allow},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleSMBIngressOnly"},
				egressRules:  []string{"allowRuleDefault"},
			},
		},
	},
	{
		testName: "direction_in_and_out_separate_rules",
		appRulesList: []data.Rule{
			{Name: "allowRuleSMBIngressOnly", Source: "frontend", Dest: "backend", Services: services("SMB", "HTTP"), Action: data.Allow, Direction: string(nsx.RuleDirectionIN)},
			{Name: "allowRuleSMBEgressOnly", Source: "frontend", Dest: "backend", Services: services("SMB"), Action: data.Allow, Direction: string(nsx.RuleDirectionOUT)},
			{Name: "denyRuleDefault", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"allowRuleSMBIngressOnly"},
				egressRules:  []string{"allowRuleSMBEgressOnly"},
			},
			{
				conn:         newTCPWithPort(httpPort),
				isAllowed:    false,
				ingressRules: []string{"allowRuleSMBIngressOnly"},
				egressRules:  []string{"denyRuleDefault"},
			},
			{
				conn:         newTCPWithPort(httpsPort),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefault"},
				egressRules:  []string{"denyRuleDefault"},
			},
		},
	},

	// todo: add tests with jump_to_app action
	{
		testName: "basic_jump_to_app_test",
		envRulesList: []data.Rule{
			{Name: "JumpToAppSMB/HTTPS", Source: "frontend", Dest: "backend", Services: services("SMB", "HTTPS"), Action: data.JumpToApp},
			{Name: "denyRuleDefaultEnv", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},

		appRulesList: []data.Rule{
			{Name: "allowSMBHTTP", Source: "frontend", Dest: "backend", Services: services("SMB", "HTTP"), Action: data.Allow},
			{Name: "denyRuleDefaultApp", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"JumpToAppSMB/HTTPS", "allowSMBHTTP"},
				egressRules:  []string{"JumpToAppSMB/HTTPS", "allowSMBHTTP"},
			},
			{
				conn:         newTCPWithPort(httpPort),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefaultEnv"},
				egressRules:  []string{"denyRuleDefaultEnv"},
			},
			{
				conn:         newTCPWithPort(httpsPort),
				isAllowed:    false,
				ingressRules: []string{"JumpToAppSMB/HTTPS", "denyRuleDefaultApp"},
				egressRules:  []string{"JumpToAppSMB/HTTPS", "denyRuleDefaultApp"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefaultEnv"},
				egressRules:  []string{"denyRuleDefaultEnv"},
			},
		},
	},
	{
		testName: "basic_jump_to_app_test_2",
		envRulesList: []data.Rule{
			{Name: "JumpToAppSMB/HTTPS", Source: "frontend", Dest: "backend", Services: services("SMB", "HTTPS"), Action: data.JumpToApp},
			{Name: "JumpToAppHTTP", Source: "frontend", Dest: "backend", Services: services("HTTP"), Action: data.JumpToApp},
			{Name: "denyRuleDefaultEnv", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},

		appRulesList: []data.Rule{
			{Name: "allowSMBHTTP", Source: "frontend", Dest: "backend", Services: services("SMB", "HTTP"), Action: data.Allow},
			{Name: "denyRuleDefaultApp", Source: anyStr, Dest: anyStr, Services: services(anyStr), Action: data.Drop},
		},
		expectedRes: []expectedExplanation{
			{
				conn:         newTCPWithPort(smbPort),
				isAllowed:    true,
				ingressRules: []string{"JumpToAppSMB/HTTPS", "allowSMBHTTP"},
				egressRules:  []string{"JumpToAppSMB/HTTPS", "allowSMBHTTP"},
			},
			{
				conn:         newTCPWithPort(httpPort),
				isAllowed:    true,
				ingressRules: []string{"JumpToAppHTTP", "allowSMBHTTP"},
				egressRules:  []string{"JumpToAppHTTP", "allowSMBHTTP"},
			},
			{
				conn:         newTCPWithPort(httpsPort),
				isAllowed:    false,
				ingressRules: []string{"JumpToAppSMB/HTTPS", "denyRuleDefaultApp"},
				egressRules:  []string{"JumpToAppSMB/HTTPS", "denyRuleDefaultApp"},
			},
			{
				conn:         netset.AllICMPTransport(),
				isAllowed:    false,
				ingressRules: []string{"denyRuleDefaultEnv"},
				egressRules:  []string{"denyRuleDefaultEnv"},
			},
		},
	},
}

func (r *rulesTest) compareActualRulesExplanation(t *testing.T, expected []string, actual []int, message string) {
	expectedIDs, err := r.rulesNamesToRulesIDs(expected)
	require.Nil(t, err)
	slices.Sort(expectedIDs)
	slices.Sort(actual)
	require.Equal(t, expectedIDs, actual, message)
}

func (r *rulesTest) rulesNamesToRulesIDs(names []string) ([]int, error) {
	res := make([]int, len(names))
	for i, name := range names {
		if id := r.ruleIDFromName(name); id >= 0 {
			res[i] = id
		} else {
			return nil, fmt.Errorf("cannot find rule name %s in rules list of rulesTest named: %s ", name, r.testName)
		}
	}

	return res, nil
}

func (r *rulesTest) ruleIDFromName(ruleName string) int {
	index := slices.IndexFunc(r.appRulesList, func(rule data.Rule) bool { return rule.Name == ruleName })
	if index < 0 {
		index = slices.IndexFunc(r.envRulesList, func(rule data.Rule) bool { return rule.Name == ruleName })
		if index < 0 {
			return -1
		}
		return index + 1
	}
	// based on example generation code, ruleID is set as "1 + the index in the rules array"
	return len(r.envRulesList) + index + 1
}

func (r *rulesTest) runTest(t *testing.T) {
	// build example from input
	overrideJSON := false
	example := basicExampleTopology.CopyTopology()
	example.Name = r.testName
	example.InitEmptyEnvAppCategories()
	for _, rule := range r.envRulesList {
		err := example.AddRuleToExampleInCategory(dfw.EnvironmentStr, &rule)
		require.Nil(t, err)
	}
	for _, rule := range r.appRulesList {
		err := example.AddRuleToExampleInCategory(dfw.ApplicationStr, &rule)
		require.Nil(t, err)
	}
	// get ResourcesContainerModel from Example object
	rc := data.ExamplesGeneration(example)
	err := example.StoreAsJSON(overrideJSON)
	require.Nil(t, err)

	connResStr, err := NSXConnectivityFromResourcesContainerPlainText(rc)
	require.Nil(t, err)
	fmt.Println(connResStr)

	configWithAnalysis, err := configFromResourcesContainer(rc, nil)
	require.Nil(t, err)

	// test explanations by comparison to expectedExplanation objects
	for i, e := range r.expectedRes {
		isAllowed, ingress, egress := configWithAnalysis.analyzedConnectivity.GetExplanationPerConnection("A", "B", e.conn)
		require.Equal(t, e.isAllowed, isAllowed, "test %s failed in isAllowed comparison of expectedRes[%d]", r.testName, i)
		r.compareActualRulesExplanation(t, e.ingressRules, ingress,
			fmt.Sprintf("test %s failed in ingressRules comparison of expectedRes[%d]", r.testName, i))
		r.compareActualRulesExplanation(t, e.egressRules, egress,
			fmt.Sprintf("test %s failed in egressRules comparison of expectedRes[%d]", r.testName, i))
	}

	disjointConns := configWithAnalysis.analyzedConnectivity.GetDisjointConnecionSetsPerExplanationsForEndpoints("A", "B")
	fmt.Printf("res: %s", common.JoinStringifiedSlice(disjointConns, "\n"))

	//nolint:gocritic // temporarily keep commented-out code
	/*isAllowed, ingress, egress := configWithAnalysis.analyzedConnectivity.GetExplanationPerConnection("A", "B", netset.AllICMPTransport())
	fmt.Printf("%v %v %v", isAllowed, ingress, egress)

	isAllowed, ingress, egress = configWithAnalysis.analyzedConnectivity.GetExplanationPerConnection("A", "B", newTCPWIthPort(smbPort))
	fmt.Printf("%v %v %v", isAllowed, ingress, egress)

	isAllowed, ingress, egress = configWithAnalysis.analyzedConnectivity.GetExplanationPerConnection("A", "B", newTCPWIthPortRange(400, 500))
	fmt.Printf("%v %v %v", isAllowed, ingress, egress)*/

	fmt.Println("done")
}

// main function to run the tests in this file
func TestAnalysisRulesExplanation(t *testing.T) {
	for i := range rulesTests {
		rulesTests[i].runTest(t)
	}
}

// todo: move these functions to another package

func newTCPWithPort(p int64) *netset.TransportSet {
	return netset.NewTCPTransport(1, 65535, p, p)
}

//nolint:unparam //  `p1` always receives `1` only currently..needs both params
func newTCPWIthPortRange(p1, p2 int64) *netset.TransportSet {
	return netset.NewTCPTransport(1, 65535, p1, p2)
}
