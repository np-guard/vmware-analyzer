package tests

import "github.com/np-guard/vmware-analyzer/pkg/collector/data"

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
						Id:       data.NewRuleID,
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
					data.DefaultDenyRule(data.DenyRuleIDEnv),
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
					data.DefaultDenyRule(data.DenyRuleIDEnv),
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
						Id:       data.NewRuleID,
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
					data.DefaultDenyRule(data.DenyRuleIDEnv),
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
						Id:       data.NewRuleID,
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
					data.DefaultDenyRule(data.DenyRuleIDEnv),
				},
			},
		},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	},
}
