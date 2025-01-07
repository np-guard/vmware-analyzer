package tests

const (
	denyRuleIDApp = 1003
	newRuleID     = 9198
)

// ExampleDumbeldore
// Dumbledore1 can communicate to all
// Dumbledore2 can communicate to all but slytherin
var ExampleDumbeldore = Example{
	vms: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	groups: map[string][]string{
		"Slytherin":       {"Slytherin"},
		"Hufflepuff":      {"Hufflepuff"},
		"Gryffindor":      {"Gryffindor"},
		"Dumbledore":      {"Dumbledore1", "Dumbledore2"},
		"DumbledoreAll":   {"Dumbledore1"},
		"DumbledoreNoSly": {"Dumbledore2"},
	},
	policies: []category{
		{
			name:         "From-Dumbledore-connection",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "Dumb1-To-All",
					id:       newRuleID,
					source:   "DumbledoreAll",
					dest:     "ANY",
					services: []string{"ANY"},
					action:   allow,
				},
				{
					name:     "Dumb2-Not-Sly",
					id:       9195,
					source:   "DumbledoreNoSly",
					dest:     "Slytherin",
					services: []string{"ANY"},
					action:   drop,
				},
				{
					name:     "Dumb2-To-All",
					id:       9196,
					source:   "DumbledoreNoSly",
					dest:     "ANY",
					services: []string{"ANY"},
					action:   allow,
				},
			},
		},

		{
			name:         "Default-L3-Section",
			categoryType: "Application",
			rules: []rule{
				defaultDenyRule(),
			},
		},
	},
}

// ExampleTwoDeniesSimple
// Simple example with two denies
// Slytherin can talk to all but Dumbledore
// Gryffindor can talk to all but Dumbledore
var ExampleTwoDeniesSimple = Example{
	vms: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	groups: map[string][]string{
		"Slytherin":   {"Slytherin"},
		"Hufflepuff":  {"Hufflepuff"},
		"Gryffindor":  {"Gryffindor"},
		"Dumbledore":  {"Dumbledore1", "Dumbledore2"},
		"Dumbledore1": {"Dumbledore1"},
		"Dumbledore2": {"Dumbledore2"},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	},
	policies: []category{
		{
			name:         "Two-Denys-Simple-Test",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "no-conn-to-dumb1",
					id:       1,
					source:   "ANY",
					dest:     "Dumbledore1",
					services: []string{"ANY"},
					action:   drop,
				},
				{
					name:     "no-conn-to-dumb2",
					id:       2,
					source:   "ANY",
					dest:     "Dumbledore2",
					services: []string{"ANY"},
					action:   drop,
				},
				{
					name:     "Slytherin-to-all",
					id:       3,
					source:   "Slytherin",
					dest:     "ANY",
					services: []string{"ANY"},
					action:   allow,
				},
				{
					name:     "Gryffindor-to-all",
					id:       4,
					source:   "Gryffindor",
					dest:     "ANY",
					services: []string{"ANY"},
					action:   allow,
				},
			},
		},
		{
			name:         "Default-L3-Section",
			categoryType: "Application",
			rules: []rule{
				defaultDenyRule(),
			},
		},
	},
}

// ExampleDenyPassSimple one pass and two denies, span over two categories
// all can talk to all but Slytherin and Hufflepuff (or to Gryffindor and Dumbledore)
var ExampleDenyPassSimple = Example{
	vms: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	groups: map[string][]string{
		"Slytherin":   {"Slytherin"},
		"Hufflepuff":  {"Hufflepuff"},
		"Gryffindor":  {"Gryffindor"},
		"Dumbledore":  {"Dumbledore1", "Dumbledore2"},
		"Dumbledore1": {"Dumbledore1"},
		"Dumbledore2": {"Dumbledore2"},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore", "Dumbledore1", "Dumbledore2"},
	},
	policies: []category{
		{
			name:         "Env-pass-and-deny",
			categoryType: "Environment",
			rules: []rule{
				{
					name:     "pass-all-to-dumb",
					id:       10218,
					source:   "ANY",
					dest:     "Dumbledore",
					services: []string{"ANY"},
					action:   jumpToApp,
				},
				{
					name:     "deny-all-to-Hufflepuff",
					id:       10219,
					source:   "ANY",
					dest:     "Hufflepuff",
					services: []string{"ANY"},
					action:   drop,
				},
				{
					name:     "deny-all-to-Slytherin",
					id:       10220,
					source:   "ANY",
					dest:     "Slytherin",
					services: []string{"ANY"},
					action:   drop,
				},
			},
		},
		{
			name:         "App-Allow-All",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "allow-all-to-all",
					id:       newRuleID,
					source:   "ANY",
					dest:     "ANY",
					services: []string{"ANY"},
					action:   allow,
				},
			},
		},
		{
			name:         "Default-L3-Section",
			categoryType: "Application",
			rules: []rule{
				defaultDenyRule(),
			},
		},
	},
}

// ExampleHintsDisjoint for testing the hint of disjoint groups/tags and relevant optimization
// Dumbledore1 can talk to all but Slytherin
// Dumbledore2 can talk to all but Gryffindor
var ExampleHintsDisjoint = Example{
	vms: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	groups: map[string][]string{
		"Slytherin":   {"Slytherin"},
		"Hufflepuff":  {"Hufflepuff"},
		"Gryffindor":  {"Gryffindor"},
		"Dumbledore1": {"Dumbledore1"},
		"Dumbledore2": {"Dumbledore2"},
	},
	DisjointGroups: [][]string{
		{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	},
	policies: []category{
		{
			name:         "From-Dumbledore-connection",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "Dumb1-Not-Sly",
					id:       newRuleID,
					source:   "Dumbledore1",
					dest:     "Slytherin",
					services: []string{"ANY"},
					action:   drop,
				},
				{
					name:     "Dumb2-Not-Gryf",
					id:       9195,
					source:   "Dumbledore2",
					dest:     "Gryffindor",
					services: []string{"ANY"},
					action:   drop,
				},
				{
					name:     "Dumb1-To-All",
					id:       9196,
					source:   "Dumbledore1",
					dest:     "ANY",
					services: []string{"ANY"},
					action:   allow,
				},
				{
					name:     "Dumb2-To-All",
					id:       9196,
					source:   "Dumbledore2",
					dest:     "ANY",
					services: []string{"ANY"},
					action:   allow,
				},
			},
		},
		{
			name:         "Default-L3-Section",
			categoryType: "Application",
			rules: []rule{
				defaultDenyRule(),
			},
		},
	},
}
