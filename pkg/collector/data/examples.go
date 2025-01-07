package data

const (
	denyRuleIDApp = 1003
	denyRuleIDEnv = 10230
	newRuleID     = 9198
)

//nolint:all
var Example1 = Example{
	VMs: []string{"A", "B"},
	Groups: map[string][]string{
		"frontend": {"A"},
		"backend":  {"B"},
	},
	Policies: []category{
		{
			name:         "app-x",
			categoryType: "Application",
			rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   "frontend",
					Dest:     "backend",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				defaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

var Example1a = Example{
	VMs: []string{"A", "B"},
	Groups: map[string][]string{
		"frontend": {"A"},
		"backend":  {"B"},
	},
	Policies: []category{
		{
			name:         "app-x",
			categoryType: "Application",
			rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   "frontend",
					Dest:     "backend",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				{
					Name:     "allow_all_frontend_to_backend",
					ID:       1005,
					Source:   "frontend",
					Dest:     "backend",
					Services: []string{"ANY"},
					Action:   Allow,
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
	VMs: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB", "Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB", "Dumbledore1", "Dumbledore2"},
	Groups: map[string][]string{
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
	Policies: []category{
		{
			name:         "Gryffindor-to-Gryffindor-allow",
			categoryType: "Environment",
			rules: []Rule{
				{
					Name:     "allow-Gryffindor-to-Gryffindor",
					ID:       10218,
					Source:   "Gryffindor",
					Dest:     "Gryffindor",
					Services: []string{"ANY"},
					Action:   JumpToApp,
				},
			},
		},
		{
			name:         "Hufflepuff-to-Hufflepuff-allow",
			categoryType: "Environment",
			rules: []Rule{
				{
					Name:     "allow-Hufflepuff-to-Hufflepuff",
					ID:       10219,
					Source:   "Hufflepuff",
					Dest:     "Hufflepuff",
					Services: []string{"ANY"},
					Action:   JumpToApp,
				},
			},
		},
		{
			name:         "Slytherin-to-Slytherin-allow",
			categoryType: "Environment",
			rules: []Rule{
				{
					Name:     "allow-Slytherin-to-Slytherin",
					ID:       10220,
					Source:   "Slytherin",
					Dest:     "Slytherin",
					Services: []string{"ANY"},
					Action:   JumpToApp,
				},
			},
		},
		{
			name:         "Gryffindor-to-Dumbledore-allow",
			categoryType: "Environment",
			rules: []Rule{
				{
					Name:     "allow-Gryffindor-to-Dumbledore",
					ID:       10216,
					Source:   "Gryffindor",
					Dest:     "Dumbledore",
					Services: []string{"ANY"},
					Action:   JumpToApp,
				},
				{
					Name:     "allow-Dumbledore-to-Gryffindor",
					ID:       10217,
					Source:   "Dumbledore",
					Dest:     "Gryffindor",
					Services: []string{"ANY"},
					Action:   JumpToApp,
				},
			},
		},

		{
			name:         "Gryffindor-Intra-App-Policy",
			categoryType: "Application",
			rules: []Rule{
				{
					Name:     "new-rule",
					ID:       newRuleID,
					Source:   "Gryffindor-App",
					Dest:     "Hufflepuff-App",
					Services: []string{"ANY"},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-Client-Access",
					ID:       9195,
					Source:   "ANY",
					Dest:     "Gryffindor-Web",
					Services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-Web-To-App-Access",
					ID:       9196,
					Source:   "Gryffindor-Web",
					Dest:     "Gryffindor-App",
					Services: []string{"/infra/services/Vmware-VC-WebAccess"},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-App-To-DB-Access",
					ID:       9197,
					Source:   "Gryffindor-App",
					Dest:     "Gryffindor-DB",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
			},
		},

		{
			name:         "Slytherin-Intra-App-Policy",
			categoryType: "Application",
			rules: []Rule{
				{
					Name:     "Slytherin-Client-Access",
					ID:       3048,
					Source:   "ANY",
					Dest:     "Slytherin-Web",
					Services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					Action:   Allow,
				},
				{
					Name:     "Slytherin-Web-To-App-Access",
					ID:       3049,
					Source:   "Slytherin-Web",
					Dest:     "Slytherin-App",
					Services: []string{"/infra/services/Vmware-VC-WebAccess"},
					Action:   Allow,
				},
				{
					Name:     "Slytherin-App-To-DB-Access",
					ID:       3050,
					Source:   "Slytherin-App",
					Dest:     "Slytherin-DB",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
			},
		},

		{
			name:         "Hufflepuff-Intra-App-Policy",
			categoryType: "Application",
			rules: []Rule{
				{
					Name:     "Hufflepuff-Client-Access",
					ID:       2048,
					Source:   "ANY",
					Dest:     "Hufflepuff-Web",
					Services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					Action:   Allow,
				},
				{
					Name:     "Hufflepuff-Web-To-App-Access",
					ID:       2049,
					Source:   "Hufflepuff-Web",
					Dest:     "Hufflepuff-App",
					Services: []string{"/infra/services/Vmware-VC-WebAccess"},
					Action:   Allow,
				},
				{
					Name:     "Hufflepuff-App-To-DB-Access",
					ID:       2050,
					Source:   "Hufflepuff-App",
					Dest:     "Hufflepuff-DB",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
			},
		},

		{
			name:         "Default-L3-Section",
			categoryType: "Application",
			rules: []Rule{
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
		rules: []Rule{
			defaultDenyRule(denyRuleIDEnv),
		},
	}
	res.Policies = append(res.Policies, defaultDenyEnvCategory)

	// change rule 9198, to have both src and dest as Gryffindor-App
	for i := range res.Policies {
		for j := range res.Policies[i].rules {
			if res.Policies[i].rules[j].ID == newRuleID {
				res.Policies[i].rules[j].Dest = "Gryffindor-App"
			}
		}
	}
	return res
}

// ExampleDumbeldore
// Dumbledore1 can communicate to all
// Dumbledore2 can communicate to all but slytherin
var ExampleDumbeldore = Example{
	VMs: []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	Groups: map[string][]string{
		"Slytherin":       {"Slytherin"},
		"Hufflepuff":      {"Hufflepuff"},
		"Gryffindor":      {"Gryffindor"},
		"Dumbledore":      {"Dumbledore1", "Dumbledore2"},
		"DumbledoreAll":   {"Dumbledore1"},
		"DumbledoreNoSly": {"Dumbledore2"},
	},
	Policies: []category{
		{
			name:         "From-Dumbledore-connection",
			categoryType: "Application",
			rules: []Rule{
				{
					Name:     "Dumb1-To-All",
					ID:       newRuleID,
					Source:   "DumbledoreAll",
					Dest:     "ANY",
					Services: []string{"ANY"},
					Action:   Allow,
				},
				{
					Name:     "Dumb2-Not-Sly",
					ID:       9195,
					Source:   "DumbledoreNoSly",
					Dest:     "Slytherin",
					Services: []string{"ANY"},
					Action:   Drop,
				},
				{
					Name:     "Dumb2-To-All",
					ID:       9196,
					Source:   "DumbledoreNoSly",
					Dest:     "ANY",
					Services: []string{"ANY"},
					Action:   Allow,
				},
			},
		},

		{
			name:         "Default-L3-Section",
			categoryType: "Application",
			rules: []Rule{
				defaultDenyRule(denyRuleIDApp),
			},
		},
	},
}
