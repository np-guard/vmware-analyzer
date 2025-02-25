package data

const (
	denyRuleIDApp = 1003
	denyRuleIDEnv = 10230
	newRuleID     = 9198
)

//nolint:all
var Example1 = Example{
	Name: "Example1",
	VMs:  []string{"A", "B"},
	GroupsByVMs: map[string][]string{
		"frontend": {"A"},
		"backend":  {"B"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   "frontend",
					Dest:     "backend",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

var Example1a = Example{
	Name: "Example1a",
	VMs:  []string{"A", "B"},
	GroupsByVMs: map[string][]string{
		"frontend": {"A"},
		"backend":  {"B"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
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
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

var Example1c = Example{
	Name: "Example1c",
	VMs:  []string{"A", "B", "C"},
	GroupsByVMs: map[string][]string{
		"frontend":  {"A"},
		"backend":   {"B"},
		"frontend1": {"C"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   "frontend",
					Dest:     "backend",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

var Example1d = Example{
	Name: "Example1d",
	VMs:  []string{"A", "B", "C"},
	GroupsByVMs: map[string][]string{
		"frontend": {"A"},
		"backend":  {"B"},
		"db":       {"C"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow_smb_incoming",
					ID:       1004,
					Source:   "frontend",
					Dest:     "backend",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				{
					Name:     "allow_https_db_incoming",
					ID:       1005,
					Source:   "backend",
					Dest:     "db",
					Services: []string{"/infra/services/HTTPS"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

/*
Example 2 with macro and micro segmentation

Slytherin House {Vms : S1, S2, S3}
Hufflepuff House {Vms: H1, H2, H3}
Gryffindor House {Vms: G1, G2, G3}
Dumbledore {Vms: D1, D2}
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
	Name: "Example2",
	VMs: []string{"Slytherin-Web", "Slytherin-App", "Slytherin-DB", "Hufflepuff-Web", "Hufflepuff-App", "Hufflepuff-DB",
		"Gryffindor-Web", "Gryffindor-App", "Gryffindor-DB", "Dumbledore1", "Dumbledore2"},
	GroupsByVMs: map[string][]string{
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
	Policies: []Category{
		{
			Name:         "Gryffindor-to-Gryffindor-allow",
			CategoryType: "Environment",
			Rules: []Rule{
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
			Name:         "Hufflepuff-to-Hufflepuff-allow",
			CategoryType: "Environment",
			Rules: []Rule{
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
			Name:         "Slytherin-to-Slytherin-allow",
			CategoryType: "Environment",
			Rules: []Rule{
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
			Name:         "Gryffindor-to-Dumbledore-allow",
			CategoryType: "Environment",
			Rules: []Rule{
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
			Name:         "Gryffindor-Intra-App-Policy",
			CategoryType: "Application",
			Rules: []Rule{
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
			Name:         "Slytherin-Intra-App-Policy",
			CategoryType: "Application",
			Rules: []Rule{
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
			Name:         "Hufflepuff-Intra-App-Policy",
			CategoryType: "Application",
			Rules: []Rule{
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
			Name:         "Default-L3-Section",
			CategoryType: "Application",
			Rules: []Rule{
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

var ExampleExclude = Example{
	Name: "ExampleExclude",
	VMs: []string{"Slytherin1", "Slytherin2", "Hufflepuff1", "Hufflepuff2",
		"Gryffindor1", "Gryffindor2", "Dumbledore1", "Dumbledore2", "Aladdin"},
	GroupsByVMs: map[string][]string{
		"Slytherin":  {"Slytherin1", "Slytherin2"},
		"Hufflepuff": {"Hufflepuff1", "Hufflepuff2"},
		"Gryffindor": {"Gryffindor1", "Gryffindor2"},
		"Dumbledore": {"Dumbledore1", "Dumbledore2"},
		"Aladdin":    {"Aladdin"},
	},
	Policies: []Category{
		{
			Name:         "AladdinTalks",
			CategoryType: "Environment",
			Rules: []Rule{
				{
					Name:                 "allow-Aladdin-to-others",
					ID:                   10218,
					Source:               "Aladdin",
					Dest:                 "Aladdin",
					DestinationsExcluded: true,
					Services:             []string{"ANY"},
					Action:               Allow,
				},
				{
					Name:            "allow-others-to-Aladdin",
					ID:              10219,
					Source:          "Aladdin",
					Dest:            "Aladdin",
					SourcesExcluded: true,
					Services:        []string{"ANY"},
					Action:          Allow,
				},
			},
		},
		{
			Name:         "Default-L3-Section",
			CategoryType: "Application",
			Rules: []Rule{
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
}

var Example3 = example3FromExample2()

func example3FromExample2() Example {
	res := Example2
	// add a default deny for env Category
	defaultDenyEnvCategory := Category{
		Name:         "defaultDenyEnvCategory",
		CategoryType: "Environment",
		Rules: []Rule{
			DefaultDenyRule(denyRuleIDEnv),
		},
	}
	res.Policies = append(res.Policies, defaultDenyEnvCategory)

	// change rule 9198, to have both src and dest as Gryffindor-App
	for i := range res.Policies {
		for j := range res.Policies[i].Rules {
			if res.Policies[i].Rules[j].ID == newRuleID {
				res.Policies[i].Rules[j].Dest = "Gryffindor-App"
			}
		}
	}
	res.Name = "Example3"
	return res
}

// ExampleDumbeldore
// Dumbledore1 can communicate to all
// Dumbledore2 can communicate to all but slytherin
var ExampleDumbeldore = Example{
	Name: "ExampleDumbeldore",
	VMs:  []string{"Slytherin", "Hufflepuff", "Gryffindor", "Dumbledore1", "Dumbledore2"},
	GroupsByVMs: map[string][]string{
		"Slytherin":       {"Slytherin"},
		"Hufflepuff":      {"Hufflepuff"},
		"Gryffindor":      {"Gryffindor"},
		"Dumbledore":      {"Dumbledore1", "Dumbledore2"},
		"DumbledoreAll":   {"Dumbledore1"},
		"DumbledoreNoSly": {"Dumbledore2"},
	},
	Policies: []Category{
		{
			Name:         "From-Dumbledore-connection",
			CategoryType: "Application",
			Rules: []Rule{
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
			Name:         "Default-L3-Section",
			CategoryType: "Application",
			Rules: []Rule{
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
}
