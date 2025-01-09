package tests

import "github.com/np-guard/vmware-analyzer/pkg/collector/data"

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
	FromNSX: data.Example{Vms: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
		Groups: map[string][]string{
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
						Id:       newRuleID,
						Source:   "DumbledoreAll",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Dumb2-Not-Sly",
						Id:       9195,
						Source:   "DumbledoreNoSly",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb2-To-All",
						Id:       9196,
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
	FromNSX: data.Example{Vms: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
		Groups: map[string][]string{
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
						Id:       1,
						Source:   "ANY",
						Dest:     "Dumbledore1",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "no-conn-to-dumb2",
						Id:       2,
						Source:   "ANY",
						Dest:     "Dumbledore2",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Slytherin-to-all",
						Id:       3,
						Source:   "Slytherin",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Gryffindor-to-all",
						Id:       4,
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
	FromNSX: data.Example{Vms: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
		Groups: map[string][]string{
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
						Id:       10218,
						Source:   "ANY",
						Dest:     "Dumbledore",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
					{
						Name:     "deny-all-to-Hufflepuff",
						Id:       10219,
						Source:   "ANY",
						Dest:     "Hufflepuff",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "deny-all-to-Slytherin",
						Id:       10220,
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
						Id:       newRuleID,
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
	FromNSX: data.Example{Vms: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
		Groups: map[string][]string{
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
						Id:       newRuleID,
						Source:   "Dumbledore1",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb2-Not-Gryf",
						Id:       9195,
						Source:   "Dumbledore2",
						Dest:     "Gryffindor",
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb1-To-All",
						Id:       9196,
						Source:   "Dumbledore1",
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Dumb2-To-All",
						Id:       9196,
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
Hufflepuff House {Vms: H1, H2, H3}
Gryffindor House {Vms: G1, G2, G3}
Dumbledore {Vms: D1, D2}
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
	FromNSX: data.Example{Vms: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB", "Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB", "Dumbledore1", "Dumbledore2"},
		Groups: map[string][]string{
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
						Id:       10218,
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
						Id:       10219,
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
						Id:       10220,
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
						Id:       10217,
						Source:   "Dumbledore",
						Dest:     "Gryffindor",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
					{
						Name:     "default-deny-env",
						Id:       10218,
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
						Id:       9195,
						Source:   "ANY",
						Dest:     "Web",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Web-To-App-Access",
						Id:       9196,
						Source:   "Web",
						Dest:     "App",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "App-To-DB-Access",
						Id:       9197,
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
	},
}

var ExampleHogwartsSimpler = ExampleSynthesis{
	FromNSX: data.Example{Vms: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB"},
		Groups: map[string][]string{
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
						Id:       10218,
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
						Id:       10220,
						Source:   "Slytherin",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
					{
						Name:     "default-deny-env",
						Id:       10218,
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
						Id:       9195,
						Source:   "ANY",
						Dest:     "Web",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Web-To-App-Access",
						Id:       9196,
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

var ExampleHogwartsNoDumbledore = ExampleSynthesis{
	FromNSX: data.Example{Vms: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB", "Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB"},
		Groups: map[string][]string{
			"Slytherin":  {"Slytherin-Web", "Slytherin-App", "Slytherin-DB"},
			"Hufflepuff": {"Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB"},
			"Gryffindor": {"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB"},
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
						Id:       10218,
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
						Id:       10219,
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
						Id:       10220,
						Source:   "Slytherin",
						Dest:     "Slytherin",
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
					{
						Name:     "default-deny-env",
						Id:       10218,
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
						Id:       9195,
						Source:   "ANY",
						Dest:     "Web",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Web-To-App-Access",
						Id:       9196,
						Source:   "Web",
						Dest:     "App",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "App-To-DB-Access",
						Id:       9197,
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
	},
}
