package tests

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	denyRuleIDEnv = 2144
	newRuleID     = 1925
)

type ExampleSynthesis struct {
	FromNSX        data.Example
	DisjointGroups [][]string
}

// ExampleDumbeldore
// Dumbledore1 can communicate to all
// Dumbledore2 can communicate to all but slytherin
var ExampleDumbeldore = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
		GroupsByVMs: map[string][]string{
			"Slytherin":       {"Slytherin"},
			"Hufflepuff":      {"Hufflepuff"},
			"Gryffindor":      {"Gryffindor"},
			"Dumbledore":      {"Dumbledore1", "Dumbledore2"},
			"DumbledoreAll":   {"Dumbledore1"},
			"DumbledoreNoSly": {"Dumbledore2"},
		},
		Policies: []data.Category{
			{
				Name:         "From-Dumbledore-connection",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Dumb1-To-All",
						ID:       newRuleID,
						Source:   "DumbledoreAll",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Dumb2-Not-Sly",
						ID:       9195,
						Source:   "DumbledoreNoSly",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb2-To-All",
						ID:       9196,
						Source:   "DumbledoreNoSly",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Default-L3-Section",
				CategoryType: "Application",
				Rules: []data.Rule{
					data.DefaultDenyRule(denyRuleIDEnv),
				},
			},
		},
	},
}

// ExampleTwoDeniesSimple
// Simple example with two denies
// Slytherin can talk to all but Dumbledore
// Gryffindor can talk to all but Dumbledore
var ExampleTwoDeniesSimple = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
		GroupsByVMs: map[string][]string{
			"Slytherin":   {"Slytherin"},
			"Hufflepuff":  {"Hufflepuff"},
			"Gryffindor":  {"Gryffindor"},
			"Dumbledore":  {"Dumbledore1", "Dumbledore2"},
			"Dumbledore1": {"Dumbledore1"},
			"Dumbledore2": {"Dumbledore2"},
		},
		Policies: []data.Category{
			{
				Name:         "Two-Denys-Simple-Test",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "no-conn-to-dumb1",
						ID:       1,
						Source:   "ANY",
						Dest:     "Dumbledore1",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "no-conn-to-dumb2",
						ID:       2,
						Source:   "ANY",
						Dest:     "Dumbledore2",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Slytherin-to-all",
						ID:       3,
						Source:   "Slytherin",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Gryffindor-to-all",
						ID:       4,
						Source:   "Gryffindor",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Default-L3-Section",
				CategoryType: "Application",
				Rules: []data.Rule{
					data.DefaultDenyRule(denyRuleIDEnv),
				},
			},
		},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	},
}

// ExampleDenyPassSimple one pass and two denies, span over two categories
// all can talk to all but Slytherin and Hufflepuff (or to Gryffindor and Dumbledore)
var ExampleDenyPassSimple = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
		GroupsByVMs: map[string][]string{
			"Slytherin":   {"Slytherin"},
			"Hufflepuff":  {"Hufflepuff"},
			"Gryffindor":  {"Gryffindor"},
			"Dumbledore":  {"Dumbledore1", "Dumbledore2"},
			"Dumbledore1": {"Dumbledore1"},
			"Dumbledore2": {"Dumbledore2"},
		},
		Policies: []data.Category{
			{
				Name:         "Env-pass-and-deny",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "pass-all-to-dumb",
						ID:       10218,
						Source:   "ANY",
						Dest:     "Dumbledore",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
					{
						Name:     "deny-all-to-Hufflepuff",
						ID:       10219,
						Source:   "ANY",
						Dest:     "Hufflepuff",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "deny-all-to-Slytherin",
						ID:       10220,
						Source:   "ANY",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
				},
			},
			{
				Name:         "App-Allow-All",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "allow-all-to-all",
						ID:       newRuleID,
						Source:   "ANY",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Default-L3-Section",
				CategoryType: "Application",
				Rules: []data.Rule{
					data.DefaultDenyRule(denyRuleIDEnv),
				},
			},
		},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore", "Dumbledore1", "Dumbledore2"},
	},
}

// ExampleHintsDisjoint for testing the hint of disjoint groups/tags and relevant optimization
// Dumbledore1 can talk to all but Slytherin
// Dumbledore2 can talk to all but Gryffindor
var ExampleHintsDisjoint = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
		GroupsByVMs: map[string][]string{
			"Slytherin":   {"Slytherin"},
			"Hufflepuff":  {"Hufflepuff"},
			"Gryffindor":  {"Gryffindor"},
			"Dumbledore1": {"Dumbledore1"},
			"Dumbledore2": {"Dumbledore2"},
		},
		Policies: []data.Category{
			{
				Name:         "From-Dumbledore-connection",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Dumb1-Not-Sly",
						ID:       newRuleID,
						Source:   "Dumbledore1",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb2-Not-Gryf",
						ID:       9195,
						Source:   "Dumbledore2",
						Dest:     "Gryffindor",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb1-To-All",
						ID:       9196,
						Source:   "Dumbledore1",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Dumb2-To-All",
						ID:       9196,
						Source:   "Dumbledore2",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Default-L3-Section",
				CategoryType: "Application",
				Rules: []data.Rule{
					data.DefaultDenyRule(denyRuleIDEnv),
				},
			},
		},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	},
}

/*
ExampleHogwarts with macro and micro segmentation

Slytherin House {Vms : S1, S2, S3}
Hufflepuff House {VMs: H1, H2, H3}
Gryffindor House {VMs: G1, G2, G3}
Dumbledore {VMs: D1, D2}
	 Web {S1, H1, G1}
	 APP {S2, H2, G2}
	 DB  {S3, H3, G3}


Macro Segmentation
- Houses (tenants / apps) must not communicate with each other
- each house must be able to communicate to Dumbledore (shared services)
- [Dumbledore must be able to communicate only to Gryffindor house (ML server / other special use case server, etc )] removed
- Within each house (tenants/apps) tiers must be able to communicate with each other

Macro Segmentation - the starting point to the land of zero trust

micro segmentation
- within each house (tenants/apps) tiers must have granular firewall policies
	- anyone can access WEB servers
	- only Web server can access App server over a whitelisted port
	- only App Server can access DB Server over a whitelisted port


*/

var ExampleHogwarts = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB", "Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB", "Dumbledore1", "Dumbledore2"},
		GroupsByVMs: map[string][]string{
			"Slytherin":  {"Slytherin-Web", "Slytherin-App", "Slytherin-DB"},
			"Hufflepuff": {"Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB"},
			"Gryffindor": {"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB"},
			"Dumbledore": {"Dumbledore1", "Dumbledore2"},
			"Web":        {"Slytherin-Web", "Gryffindor-Web", "Hufflepuff-Web"},
			"App":        {"Slytherin-App", "Gryffindor-App", "Hufflepuff-App"},
			"DB":         {"Slytherin-DB", "Gryffindor-DB", "Hufflepuff-DB"},
		},
		Policies: []data.Category{
			{
				Name:         "Gryffindor-to-Gryffindor-allow",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "allow-Gryffindor-to-Gryffindor",
						ID:       10218,
						Source:   "Gryffindor",
						Dest:     "Gryffindor",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
				},
			},
			{
				Name:         "Hufflepuff-to-Hufflepuff-allow",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "allow-Hufflepuff-to-Hufflepuff",
						ID:       10219,
						Source:   "Hufflepuff",
						Dest:     "Hufflepuff",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
				},
			},
			{
				Name:         "Slytherin-to-Slytherin-allow",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "allow-Slytherin-to-Slytherin",
						ID:       10220,
						Source:   "Slytherin",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
				},
			},
			{
				Name:         "Dumbledore-connection",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "allow-Dumbledore-to-all",
						ID:       10217,
						Source:   "Dumbledore",
						Dest:     "Gryffindor",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
					{
						Name:     "default-deny-env",
						ID:       10218,
						Source:   "ANY",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
				},
			},

			{
				Name:         "Intra-App-Policy",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Client-Access",
						ID:       9195,
						Source:   "ANY",
						Dest:     "Web",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Web-To-App-Access",
						ID:       9196,
						Source:   "Web",
						Dest:     "App",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "App-To-DB-Access",
						ID:       9197,
						Source:   "App",
						Dest:     "DB",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Default-L3-Section",
				CategoryType: "Application",
				Rules: []data.Rule{
					data.DefaultDenyRule(denyRuleIDEnv),
				},
			},
		},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore"},
		{"Web", "App", "DB"},
		{"Web", "Dumbledore"},
		{"App", "Dumbledore"},
		{"DB", "Dumbledore"},
	},
}

var ExampleHogwartsSimpler = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB"},
		GroupsByVMs: map[string][]string{
			"Slytherin":  {"Slytherin-Web", "Slytherin-App"},
			"Gryffindor": {"Gryffindor-Web", "Gryffindor-App"},
			"Web":        {"Slytherin-Web", "Gryffindor-Web"},
			"App":        {"Slytherin-App", "Gryffindor-App"},
		},
		Policies: []data.Category{
			{
				Name:         "Gryffindor-to-Gryffindor-allow",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "allow-Gryffindor-to-Gryffindor",
						ID:       10218,
						Source:   "Gryffindor",
						Dest:     "Gryffindor",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
				},
			},
			{
				Name:         "Slytherin-to-Slytherin-allow",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "allow-Slytherin-to-Slytherin",
						ID:       10220,
						Source:   "Slytherin",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
					{
						Name:     "default-deny-env",
						ID:       10218,
						Source:   "ANY",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
				},
			},
			{
				Name:         "Intra-App-Policy",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Client-Access",
						ID:       9195,
						Source:   "ANY",
						Dest:     "Web",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Web-To-App-Access",
						ID:       9196,
						Source:   "Web",
						Dest:     "App",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Default-L3-Section",
				CategoryType: "Application",
				Rules: []data.Rule{
					data.DefaultDenyRule(denyRuleIDEnv),
				},
			},
		},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore"},
		{"Web", "App", "DB"},
	},
}

var hogwartsAppToHousesPolicy = []data.Category{
	{
		Name:         "Gryffindor-to-Gryffindor-allow",
		CategoryType: "Environment",
		Rules: []data.Rule{
			{
				Name:     "allow-Gryffindor-to-Gryffindor",
				ID:       10218,
				Source:   "Gryffindor",
				Dest:     "Gryffindor",
				Services: []string{"ANY"},
				Action:   data.JumpToApp,
			},
		},
	},
	{
		Name:         "Hufflepuff-to-Hufflepuff-allow",
		CategoryType: "Environment",
		Rules: []data.Rule{
			{
				Name:     "allow-Hufflepuff-to-Hufflepuff",
				ID:       10219,
				Source:   "Hufflepuff",
				Dest:     "Hufflepuff",
				Services: []string{"ANY"},
				Action:   data.JumpToApp,
			},
		},
	},
	{
		Name:         "Slytherin-to-Slytherin-allow",
		CategoryType: "Environment",
		Rules: []data.Rule{
			{
				Name:     "allow-Slytherin-to-Slytherin",
				ID:       10220,
				Source:   "Slytherin",
				Dest:     "Slytherin",
				Services: []string{"ANY"},
				Action:   data.JumpToApp,
			},
			{
				Name:     "default-deny-env",
				ID:       10218,
				Source:   "ANY",
				Dest:     "ANY",
				Services: []string{"ANY"},
				Action:   data.Drop,
			},
		},
	},
	{
		Name:         "Intra-App-Policy",
		CategoryType: "Application",
		Rules: []data.Rule{
			{
				Name:     "Client-Access",
				ID:       9195,
				Source:   "ANY",
				Dest:     "Web",
				Services: []string{"ANY"},
				Action:   data.Allow,
			},
			{
				Name:     "Web-To-App-Access",
				ID:       9196,
				Source:   "Web",
				Dest:     "App",
				Services: []string{"ANY"},
				Action:   data.Allow,
			},
			{
				Name:     "App-To-DB-Access",
				ID:       9197,
				Source:   "App",
				Dest:     "DB",
				Services: []string{"ANY"},
				Action:   data.Allow,
			},
		},
	},
	{
		Name:         "Default-L3-Section",
		CategoryType: "Application",
		Rules: []data.Rule{
			data.DefaultDenyRule(denyRuleIDEnv),
		},
	},
}

var ExampleHogwartsNoDumbledore = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB", "Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB"},
		GroupsByVMs: map[string][]string{
			"Slytherin":  {"Slytherin-Web", "Slytherin-App", "Slytherin-DB"},
			"Hufflepuff": {"Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB"},
			"Gryffindor": {"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB"},
			"Web":        {"Slytherin-Web", "Gryffindor-Web", "Hufflepuff-Web"},
			"App":        {"Slytherin-App", "Gryffindor-App", "Hufflepuff-App"},
			"DB":         {"Slytherin-DB", "Gryffindor-DB", "Hufflepuff-DB"},
		},
		Policies: hogwartsAppToHousesPolicy,
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore"},
		{"Web", "App", "DB"},
	},
}

// examples with expr instead of direct vms references

var ExampleExprSingleScope = ExampleSynthesis{
	FromNSX: data.Example{
		Name: "ExampleExprSimple",
		VMs:  []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore"},
		VMsTags: map[string][]nsx.Tag{"Slytherin": {{Tag: "Slytherin"}}, "Hufflepuff": {{Tag: "Hufflepuff"}},
			"Gryffindor": {{Tag: "Gryffindor"}}, "Dumbledore": {{Tag: "Dumbledore"}}},
		GroupsByExpr: map[string]data.ExampleExpr{
			"Slytherin":  {Cond1: data.ExampleCond{Tag: nsx.Tag{Tag: "Slytherin"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
			"Gryffindor": {Cond1: data.ExampleCond{Tag: nsx.Tag{Tag: "Gryffindor"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
			"Hufflepuff": {Cond1: data.ExampleCond{Tag: nsx.Tag{Tag: "Hufflepuff"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
			"Dumbledore": {Cond1: data.ExampleCond{Tag: nsx.Tag{Tag: "Dumbledore"}}, Op: data.Nop, Cond2: data.ExampleCond{}}},
		Policies: []data.Category{
			{
				Name:         "From-Dumbledore-connection",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Dumb-No-Slytherin",
						ID:       newRuleID,
						Source:   "Dumbledore",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb-All",
						ID:       9195,
						Source:   "DumbledoreNoSly",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Gryffindor-connections",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Gryffindor-not-Hufflepuff",
						ID:       newRuleID,
						Source:   "Gryffindor",
						Dest:     "Hufflepuff",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Gryffindor-All",
						ID:       9195,
						Source:   "Gryffindor",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Hufflepuff-connection",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Hufflepuff-No-Slytherin",
						ID:       newRuleID,
						Source:   "Hufflepuff",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Hufflepuff-All",
						ID:       9195,
						Source:   "Hufflepuff",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Slytherin-connection",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Slytherin-no-Gryffindor",
						ID:       newRuleID,
						Source:   "Slytherin",
						Dest:     "Gryffindor",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Slytherin-All",
						ID:       9195,
						Source:   "Slytherin",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
				},
			},
			{
				Name:         "Default-L3-Section",
				CategoryType: "Application",
				Rules: []data.Rule{
					data.DefaultDenyRule(denyRuleIDEnv),
				},
			},
		},
	},
}

var vmsHousesTags = map[string][]nsx.Tag{"Slytherin-DB": {{Scope: "House", Tag: "Slytherin"}, {Scope: "function", Tag: "DB"}},
	"Slytherin-Web":  {{Scope: "House", Tag: "Slytherin"}, {Scope: "function", Tag: "Web"}},
	"Slytherin-App":  {{Scope: "House", Tag: "Slytherin"}, {Scope: "function", Tag: "App"}},
	"Hufflepuff-DB":  {{Scope: "House", Tag: "Hufflepuff"}, {Scope: "function", Tag: "DB"}},
	"Hufflepuff-Web": {{Scope: "House", Tag: "Hufflepuff"}, {Scope: "function", Tag: "Web"}},
	"Hufflepuff-App": {{Scope: "House", Tag: "Hufflepuff"}, {Scope: "function", Tag: "App"}},
	"Gryffindor-DB":  {{Scope: "House", Tag: "Gryffindor"}, {Scope: "function", Tag: "DB"}},
	"Gryffindor-Web": {{Scope: "House", Tag: "Gryffindor"}, {Scope: "function", Tag: "Web"}},
	"Gryffindor-App": {{Scope: "House", Tag: "Gryffindor"}, {Scope: "function", Tag: "App"}}}

var ExampleExprTwoScopes = ExampleSynthesis{FromNSX: data.Example{
	Name: "ExampleExprSimple",
	VMs: []string{"Slytherin-DB", "Slytherin-Web", "Slytherin-App",
		"Hufflepuff-DB", "Hufflepuff-Web", "Hufflepuff-App",
		"Gryffindor-DB", "Gryffindor-Web", "Gryffindor-App"},
	VMsTags: vmsHousesTags,
	GroupsByExpr: map[string]data.ExampleExpr{
		"Slytherin":  {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Slytherin"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"Gryffindor": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Gryffindor"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"Hufflepuff": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Hufflepuff"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"Dumbledore": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Dumbledore"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"DB":         {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "function", Tag: "DB"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"Web":        {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "function", Tag: "Web"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"App":        {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "function", Tag: "App"}}, Op: data.Nop, Cond2: data.ExampleCond{}}},
	Policies: hogwartsAppToHousesPolicy,
},
}

var vmsHouses = []string{"Slytherin-DB", "Slytherin-Web", "Slytherin-App",
	"Hufflepuff-DB", "Hufflepuff-Web", "Hufflepuff-App",
	"Gryffindor-DB", "Gryffindor-Web", "Gryffindor-App"}

// ExampleExprAndConds todo: this example uses not yet supported scope
var ExampleExprAndConds = ExampleSynthesis{FromNSX: data.Example{
	Name:         "ExampleExprAndConds",
	VMs:          vmsHouses,
	VMsTags:      vmsHousesTags,
	GroupsByExpr: andOrOrExpr(data.And),
	Policies:     andOrOrPolicies,
},
}

// ExampleExprOrConds todo: this example uses not yet supported scope
var ExampleExprOrConds = ExampleSynthesis{FromNSX: data.Example{
	Name:         "ExampleOrSimple",
	VMs:          vmsHouses,
	VMsTags:      vmsHousesTags,
	GroupsByExpr: andOrOrExpr(data.Or),
	Policies:     andOrOrPolicies,
},
}

func andOrOrExpr(op data.ExampleOp) map[string]data.ExampleExpr {
	return map[string]data.ExampleExpr{
		"Slytherin":  {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Slytherin"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"Gryffindor": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Gryffindor"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"Hufflepuff": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Hufflepuff"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"Dumbledore": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Dumbledore"}}, Op: data.Nop, Cond2: data.ExampleCond{}},
		"Slytherin-orOrAnd-no-DB": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Slytherin"}}, Op: op,
			Cond2: data.ExampleCond{Tag: nsx.Tag{Scope: "function", Tag: "DB"}, NotEqual: true}},
		"Hufflepuff-orOrAnd-no-DB": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Hufflepuff"}}, Op: op,
			Cond2: data.ExampleCond{Tag: nsx.Tag{Scope: "function", Tag: "DB"}, NotEqual: true}},
		"Gryffindor-orOrAnd-no-DB": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: "House", Tag: "Gryffindor"}}, Op: op,
			Cond2: data.ExampleCond{Tag: nsx.Tag{Scope: "function", Tag: "DB"}, NotEqual: true}}}
}

var andOrOrPolicies = []data.Category{
	{
		Name:         "Protect-DBs",
		CategoryType: "Application",
		Rules: []data.Rule{
			{
				Name:     "to-Slytherin",
				ID:       10218,
				Source:   "ANY",
				Dest:     "Slytherin-orOrAnd-no-DB",
				Services: []string{"ANY"},
				Action:   data.Allow,
			},
			{
				Name:     "to-Gryffindor",
				ID:       10218,
				Source:   "ANY",
				Dest:     "Gryffindor-orOrAnd-no-DB",
				Services: []string{"ANY"},
				Action:   data.Allow,
			},
			{
				Name:     "to-Hufflepuff",
				ID:       10218,
				Source:   "ANY",
				Dest:     "Hufflepuff-orOrAnd-no-DB",
				Services: []string{"ANY"},
				Action:   data.Allow,
			},
		},
	},
	{
		Name:         "Default-L3-Section",
		CategoryType: "Application",
		Rules: []data.Rule{
			data.DefaultDenyRule(denyRuleIDEnv),
		},
	},
}
