package data

const (
	denyRuleIDApp = 1003
	denyRuleIDEnv = 10230
	newRuleID     = 9198
)

//nolint:all
var Example1 = Example{
	vms: []string{"A", "B"},
	groups: map[string][]string{
		"frontend": {"A"},
		"backend":  {"B"},
	},
	policies: []category{
		{
			name:         "app-x",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "allow_smb_incoming",
					id:       1004,
					source:   "frontend",
					dest:     "backend",
					services: []string{"/infra/services/SMB"},
					action:   allow,
				},
				defaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

/*
Example 2 with macro and micro segmentation

Slytherin House {vms : S1, S2, S3}
Hufflepuff House {vms: H1, H2, H3}
Gryffindor House {vms: G1, G2, G3}
Dumbledore {vms: D1, D2}
	Slytherin Web {S1}
	Slytherin APP {S2}
	Slytherin DB  {S3}


Macro Segmentation
- Houses (tenants / apps) must not communicate with each other
- each house must be able to communicate to Hogwarts (shared services)
- only Gryffindor house must be able to communicate to Dumbledore (ML server / other special use case server, etc )
- Within each house (tenants/apps) tiers must be able to communicate with each other

Macro Segmentation - the starting point to the land of zero trust

micro segmentation
- within each house (tenants/apps) tiers must have granular firewall policies
	- anyone can access WEB servers
	- only Web server can access App server over a whitelisted port
	- only App Server can access DB Server over a whitelisted port


*/

var Example2 = Example{
	vms: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB", "Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB", "Dumbledore1", "Dumbledore2"},
	groups: map[string][]string{
		"Slytherin":      {"Slytherin-Web", "Slytherin-App", "Slytherin-DB"},
		"Hufflepuff":     {"Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB"},
		"Gryffindor":     {"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB"},
		"Dumbledore":     {"Dumbledore1", "Dumbledore2"},
		"Slytherin-Web":  {"Slytherin-Web"},
		"Slytherin-App":  {"Slytherin-App"},
		"Slytherin-DB":   {"Slytherin-DB"},
		"Gryffindor-Web": {"Gryffindor-Web"},
		"Gryffindor-App": {"Gryffindor-App"},
		"Gryffindor-DB":  {"Gryffindor-DB"},
		"Hufflepuff-Web": {"Hufflepuff-Web"},
		"Hufflepuff-App": {"Hufflepuff-App"},
		"Hufflepuff-DB":  {"Hufflepuff-DB"},
	},
	policies: []category{
		{
			name:         "Gryffindor-to-Gryffindor-allow",
			categoryType: "Environment",
			rules: []rule{
				{
					name:     "allow-Gryffindor-to-Gryffindor",
					id:       10218,
					source:   "Gryffindor",
					dest:     "Gryffindor",
					services: []string{"ANY"},
					action:   jumpToApp,
				},
			},
		},
		{
			name:         "Hufflepuff-to-Hufflepuff-allow",
			categoryType: "Environment",
			rules: []rule{
				{
					name:     "allow-Hufflepuff-to-Hufflepuff",
					id:       10219,
					source:   "Hufflepuff",
					dest:     "Hufflepuff",
					services: []string{"ANY"},
					action:   jumpToApp,
				},
			},
		},
		{
			name:         "Slytherin-to-Slytherin-allow",
			categoryType: "Environment",
			rules: []rule{
				{
					name:     "allow-Slytherin-to-Slytherin",
					id:       10220,
					source:   "Slytherin",
					dest:     "Slytherin",
					services: []string{"ANY"},
					action:   jumpToApp,
				},
			},
		},
		{
			name:         "Gryffindor-to-Dumbledore-allow",
			categoryType: "Environment",
			rules: []rule{
				{
					name:     "allow-Gryffindor-to-Dumbledore",
					id:       10216,
					source:   "Gryffindor",
					dest:     "Dumbledore",
					services: []string{"ANY"},
					action:   jumpToApp,
				},
				{
					name:     "allow-Dumbledore-to-Gryffindor",
					id:       10217,
					source:   "Dumbledore",
					dest:     "Gryffindor",
					services: []string{"ANY"},
					action:   jumpToApp,
				},
			},
		},

		{
			name:         "Gryffindor-Intra-App-Policy",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "new-rule",
					id:       newRuleID,
					source:   "Gryffindor-App",
					dest:     "Hufflepuff-App",
					services: []string{"ANY"},
					action:   allow,
				},
				{
					name:     "Gryffindor-Client-Access",
					id:       9195,
					source:   "ANY",
					dest:     "Gryffindor-Web",
					services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					action:   allow,
				},
				{
					name:     "Gryffindor-Web-To-App-Access",
					id:       9196,
					source:   "Gryffindor-Web",
					dest:     "Gryffindor-App",
					services: []string{"/infra/services/Vmware-VC-WebAccess"},
					action:   allow,
				},
				{
					name:     "Gryffindor-App-To-DB-Access",
					id:       9197,
					source:   "Gryffindor-App",
					dest:     "Gryffindor-DB",
					services: []string{"/infra/services/SMB"},
					action:   allow,
				},
			},
		},

		{
			name:         "Slytherin-Intra-App-Policy",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "Slytherin-Client-Access",
					id:       3048,
					source:   "ANY",
					dest:     "Slytherin-Web",
					services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					action:   allow,
				},
				{
					name:     "Slytherin-Web-To-App-Access",
					id:       3049,
					source:   "Slytherin-Web",
					dest:     "Slytherin-App",
					services: []string{"/infra/services/Vmware-VC-WebAccess"},
					action:   allow,
				},
				{
					name:     "Slytherin-App-To-DB-Access",
					id:       3050,
					source:   "Slytherin-App",
					dest:     "Slytherin-DB",
					services: []string{"/infra/services/SMB"},
					action:   allow,
				},
			},
		},

		{
			name:         "Hufflepuff-Intra-App-Policy",
			categoryType: "Application",
			rules: []rule{
				{
					name:     "Hufflepuff-Client-Access",
					id:       2048,
					source:   "ANY",
					dest:     "Hufflepuff-Web",
					services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					action:   allow,
				},
				{
					name:     "Hufflepuff-Web-To-App-Access",
					id:       2049,
					source:   "Hufflepuff-Web",
					dest:     "Hufflepuff-App",
					services: []string{"/infra/services/Vmware-VC-WebAccess"},
					action:   allow,
				},
				{
					name:     "Hufflepuff-App-To-DB-Access",
					id:       2050,
					source:   "Hufflepuff-App",
					dest:     "Hufflepuff-DB",
					services: []string{"/infra/services/SMB"},
					action:   allow,
				},
			},
		},

		{
			name:         "Default-L3-Section",
			categoryType: "Application",
			rules: []rule{
				defaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

var Example3 = example3FromExample2()

func example3FromExample2() Example {
	res := Example2
	// add a default deny for env category
	defaultDenyEnvCategory := category{
		name:         "defaultDenyEnvCategory",
		categoryType: "Environment",
		rules: []rule{
			defaultDenyRule(denyRuleIDEnv),
		},
	}
	res.policies = append(res.policies, defaultDenyEnvCategory)

	// change rule 9198, to have both src and dest as Gryffindor-App
	for _, c := range res.policies {
		for _, r := range c.rules {
			if r.id == newRuleID {
				r.dest = "Gryffindor-App"
			}
		}
	}
	return res
}

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
				defaultDenyRule(denyRuleIDApp),
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
				defaultDenyRule(denyRuleIDApp),
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
				defaultDenyRule(denyRuleIDApp),
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
				defaultDenyRule(denyRuleIDApp),
			},
		},
	},
}
