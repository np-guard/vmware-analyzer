package data

import nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"

// focusing here on various groups types examples

//nolint:all
var ExampleGroup1 = registerExample(&Example{
	// ExampleGroup1 has "external-group" of type IPAddresses
	Name: "ExampleGroup1",
	VMs:  []string{"A", "B"},
	GroupsByVMs: map[string][]string{
		frontEnd: {"A"},
		backEnd:  {"B"},
	},
	GroupsOfIPAddresses: map[string][]nsx.IPElement{
		"external-group": {"8.8.8.8/32"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   frontEnd,
					Dest:     backEnd,
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				{
					Name:     "allow_external_to_frontend",
					ID:       1005,
					Source:   "external-group",
					Dest:     frontEnd,
					Services: []string{"/infra/services/HTTP"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

/////////////////////////////////////////////////////////////////////////////////////

var ExampleGroup2 = registerExample(&Example{
	// ExampleGroup2 has "A-by-IP" group of type IPAddresses
	Name: "ExampleGroup2",
	VMs:  []string{"A", "B"},
	VMsAddress: map[string]string{
		"A": "192.168.10.5",
		"B": "192.168.10.6",
	},
	GroupsByVMs: map[string][]string{
		frontEnd: {"A"},
		backEnd:  {"B"},
	},
	GroupsOfIPAddresses: map[string][]nsx.IPElement{
		"external-group": {"8.8.8.8/32"},
		"A-by-IP":        {"192.168.10.5"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   "A-by-IP",
					Dest:     backEnd,
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

/////////////////////////////////////////////////////////////////////////////////////

var ExampleGroup3 = registerExample(&Example{
	// "path-group" is a group that selects path to segment and path to another group
	Name: "ExampleGroup3",
	VMs:  []string{"New-VM-1", "New-VM-2", "New-VM-3", "New-VM-4", "New Virtual Machine"},
	GroupsByVMs: map[string][]string{
		"research-app":         {"New-VM-1", "New-VM-2", "New-VM-3", "New-VM-4", "New Virtual Machine"},
		"research-seg-1":       {"New-VM-1", "New-VM-3", "New-VM-4"},
		"foo-app":              {"New-VM-3", "New-VM-4"},
		"foo-backend":          {"New-VM-4"},
		"foo-frontend":         {"New-VM-3"},
		"research-test-expr-2": {"New Virtual Machine"},
	},
	GroupByPathExpr: map[string][]string{
		"path-group": {
			"foo-app", // path to another group to be included in this group
			"seg1",    // path to another segment to be included in this group
		},
	},
	SegmentsByVMs: map[string][]string{
		"seg1": {"New-VM-1", "New-VM-2"},
	},
	SegmentsBlock: map[string]string{
		"seg1": "192.168.1.0/24",
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   "path-group",
					Dest:     "research-test-expr-2",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

// ///////////////////////////////////////////////////////////////////////////////////
var ExampleGroup4 = registerExample(&Example{
	// "path-group" is a group that selects path to segment and path to another group
	Name: "ExampleGroup4",
	VMs:  []string{"New-VM-1", "New-VM-2", "New-VM-3", "New-VM-4", "New Virtual Machine"},
	VMsTags: map[string][]nsx.Tag{
		"New-VM-3": {{Tag: "foo"}},
		"New-VM-4": {{Tag: "foo"}, {Tag: "bar"}},
		"New-VM-1": {{Tag: "bar"}},
		"New-VM-2": {{Tag: "backend"}},
	},
	GroupsByVMs: map[string][]string{
		"research-test-expr-2": {"New Virtual Machine"},
	},
	GroupByNestedExpr: map[string]ExampleExpr{
		"nested-expr-group": {
			Cond1: &ExampleNestedExpr{
				expr: ExampleExpr{
					Cond1: &ExampleCond{
						Tag: nsx.Tag{Tag: "foo"},
					},
					Op: And,
					Cond2: &ExampleCond{
						Tag: nsx.Tag{Tag: "bar"},
					},
				},
			},
			Op: Or,
			Cond2: &ExampleCond{
				Tag: nsx.Tag{Tag: "backend"},
			},
		},
	},

	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   "nested-expr-group",
					Dest:     "research-test-expr-2",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var ExampleHogwartsNestedExpr = registerExample(&Example{
	Name:         "ExampleHogwartsNestedExpr",
	GroupsByExpr: twoScopeGroupsByExpr,
	GroupByNestedExpr: map[string]ExampleExpr{
		"hogwarts-nested-expr-group": {
			Cond1: &ExampleNestedExpr{
				expr: ExampleExpr{
					Cond1: &ExampleCond{
						Tag: nsx.Tag{Tag: sly},
					},
					Op: And,
					Cond2: &ExampleCond{
						Tag: nsx.Tag{Tag: db},
					},
				},
			},
			Op: Or,
			Cond2: &ExampleNestedExpr{
				expr: ExampleExpr{
					Cond1: &ExampleCond{
						Tag: nsx.Tag{Tag: gry},
					},
					Op: And,
					Cond2: &ExampleCond{
						Tag: nsx.Tag{Tag: web},
					},
				},
			},
		},
	},
	VMsTags: vmsHousesTags,
	Policies: []Category{
		{
			Name:         "app-rules",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "allow1",
					ID:       9195,
					Source:   "hogwarts-nested-expr-group",
					Dest:     "hogwarts-nested-expr-group",
					Services: []string{AnyStr},
					Action:   Allow,
				},
				{
					Name:     "deny1",
					ID:       9196,
					Source:   sly,
					Dest:     gry,
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "allow2",
					ID:       9197,
					Source:   web,
					Dest:     app,
					Services: []string{AnyStr},
					Action:   Allow,
				},
			},
		},
		{
			Name:         defaultL3,
			CategoryType: application,
			Rules: []Rule{
				DefaultDenyRule(denyRuleIDEnv),
			},
		},
	},
	DisjointGroupsTags: disjointHousesAndFunctionality,
})
