package data

import (
	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

const (
	denyRuleIDApp = 1003
	denyRuleIDEnv = 10230
	newRuleID     = 9198
)

const (
	sly  = "Slytherin"
	huf  = "Hufflepuff"
	gry  = "Gryffindor"
	dum  = "Dumbledore"
	dum1 = "Dumbledore1"
	dum2 = "Dumbledore2"

	house = "House"
	funct = "Function"
	db    = "DB"
	app   = "App"
	web   = "Web"

	slyDB  = "Slytherin-DB"
	slyApp = "Slytherin-App"
	slyWeb = "Slytherin-Web"
	gryDB  = "Gryffindor-DB"
	gryApp = "Gryffindor-App"
	gryWeb = "Gryffindor-Web"
	hufDB  = "Hufflepuff-DB"
	hufApp = "Hufflepuff-App"
	hufWeb = "Hufflepuff-Web"
)

const (
	anyStr      = "ANY"
	application = "Application"
	environment = "Environment"
	defaultL3   = "Default-L3-Section"

	frontEnd = "frontend"
	backEnd  = "backend"
)

var allExamples = map[int]*Example{}
var examplesCount = 0

func registerExample(e *Example) *Example {
	allExamples[examplesCount] = e
	examplesCount++
	return e
}

//nolint:all
var Example1 = registerExample(&Example{
	Name: "Example1",
	VMs:  []string{"A", "B"},
	GroupsByVMs: map[string][]string{
		frontEnd: {"A"},
		backEnd:  {"B"},
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
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var Example1a = registerExample(&Example{
	Name: "Example1a",
	VMs:  []string{"A", "B"},
	GroupsByVMs: map[string][]string{
		frontEnd: {"A"},
		backEnd:  {"B"},
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
					Name:     "allow_all_frontend_to_backend",
					ID:       1005,
					Source:   frontEnd,
					Dest:     backEnd,
					Services: []string{anyStr},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var Example1c = registerExample(&Example{
	Name: "Example1c",
	VMs:  []string{"A", "B", "C"},
	GroupsByVMs: map[string][]string{
		frontEnd:    {"A"},
		backEnd:     {"B"},
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
					Source:   frontEnd,
					Dest:     backEnd,
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var Example1d = registerExample(&Example{
	Name: "Example1d",
	VMs:  []string{"A", "B", "C"},
	GroupsByVMs: map[string][]string{
		frontEnd: {"A"},
		backEnd:  {"B"},
		"db":     {"C"},
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
					Name:     "allow_https_db_incoming",
					ID:       1005,
					Source:   backEnd,
					Dest:     "db",
					Services: []string{"/infra/services/HTTPS"},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var Example1dExternalWithSegments = registerExample(&Example{
	Name:        "Example1dExternalWithSegments",
	VMs:         []string{"A", "B", "C-no-address"},
	GroupsByVMs: map[string][]string{"default-group": {"A", "B", "C-no-address"}},
	VMsAddress: map[string]string{
		"A": "0.0.1.0",
		"B": "0.0.1.192",
	},
	SegmentsByVMs: map[string][]string{
		"seg_a_and_b": {"A", "B"},
		"seg_c":       {"C-no-address"},
	},
	SegmentsBlock: map[string]string{
		"seg_a_and_b": "0.0.1.0/24",
		"seg_c":       "0.0.2.0/24",
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow_smb_a_to_b",
					ID:       1004,
					Source:   "0.0.1.0/25",
					Dest:     "0.0.1.128/25",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				{
					Name:     "allow_https_b_to_c",
					ID:       1005,
					Source:   "0.0.1.128/25",
					Dest:     "0.0.2.0/24",
					Services: []string{"/infra/services/HTTPS"},
					Action:   Allow,
				},
				{
					Name:   "allow_icmp_all",
					ID:     1006,
					Source: "0.0.0.0/0",
					Dest:   "0.0.0.0/0",
					Conn:   netset.AllICMPTransport(),
					Action: Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var Example1External = registerExample(&Example{
	Name: "Example1External",
	VMs:  []string{"A"},
	GroupsByVMs: map[string][]string{
		frontEnd: {"A"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:   "allow_tcp_0_1",
					ID:     1004,
					Source: "1.2.0.0-1.2.1.255",
					Dest:   frontEnd,
					Conn:   netset.AllTCPTransport(),
					Action: Allow,
				},
				{
					Name:   "allow_udp_3_4",
					ID:     1005,
					Source: "1.2.3.0-1.2.4.255",
					Dest:   frontEnd,
					Conn:   netset.AllUDPTransport(),
					Action: Allow,
				},
				{
					Name:   "allow_icmp_1_3",
					ID:     1006,
					Source: "1.2.1.0-1.2.3.255",
					Dest:   frontEnd,
					Conn:   netset.AllICMPTransport(),
					Action: Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var ExampleExternalWithDenySimple = registerExample(&Example{
	Name: "ExampleExternalWithDenySimple",
	VMs:  []string{"A"},
	GroupsByVMs: map[string][]string{
		frontEnd: {"A"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:   "deny_tcp_0_1",
					ID:     1004,
					Source: "1.2.0.0/30",
					Dest:   frontEnd,
					Conn:   netset.AllTCPTransport(),
					Action: Drop,
				},
				{
					Name:   "allow_tcp_0_1",
					ID:     1005,
					Source: "1.2.0.0-1.2.1.255",
					Dest:   frontEnd,
					Conn:   netset.AllTCPTransport(),
					Action: Allow,
				},
				{
					Name:   "allow_udp_3_4",
					ID:     1006,
					Source: "1.2.3.0-1.2.4.255",
					Dest:   frontEnd,
					Conn:   netset.AllUDPTransport(),
					Action: Allow,
				},
				{
					Name:   "allow_icmp_1_3",
					ID:     1007,
					Source: "1.2.1.0-1.2.3.255",
					Dest:   frontEnd,
					Conn:   netset.AllICMPTransport(),
					Action: Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

/*func getExampleExternalWithDenySimple(useScope bool) *map[string]ExampleExpr {
	dst, scope :=
	if useScope {

	} else {

	}

}*/

var ExampleExternalSimpleWithInterlDenyAllow = registerExample(&Example{
	Name: "ExampleExternalSimpleWithInterlDenyAllow",
	VMs:  []string{"A"},
	GroupsByVMs: map[string][]string{
		frontEnd: {"A"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Environment",
			Rules: []Rule{
				{
					Name:      "deny_tcp_0_1",
					ID:        1004,
					Source:    "1.2.0.0/30",
					Dest:      frontEnd,
					Conn:      netset.AllTCPTransport(),
					Action:    Drop,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow_tcp_0_1",
					ID:        1005,
					Source:    "1.2.0.0/24",
					Dest:      frontEnd,
					Conn:      netset.AllTCPTransport(),
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "deny_all_conn_0_1",
					ID:        1006,
					Source:    "1.2.0.0/24",
					Dest:      frontEnd,
					Conn:      netset.AllTransports(),
					Action:    Drop,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow_all_conn_0_1",
					ID:        1007,
					Source:    "1.2.0.0/16",
					Dest:      frontEnd,
					Conn:      netset.AllTransports(),
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
			},
		},
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:      "deny_tcp_0_2",
					ID:        1008,
					Source:    "1.240.0.0/28",
					Dest:      frontEnd,
					Conn:      netset.AllTCPTransport(),
					Action:    Drop,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow_all_conn_0_2",
					ID:        1009,
					Source:    "1.240.0.0/28",
					Dest:      frontEnd,
					Conn:      netset.AllTransports(),
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var ExampleExclude = registerExample(&Example{
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
					Services:             []string{anyStr},
					Action:               Allow,
				},
				{
					Name:            "allow-others-to-Aladdin",
					ID:              10219,
					Source:          "Aladdin",
					Dest:            "Aladdin",
					SourcesExcluded: true,
					Services:        []string{anyStr},
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
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

var Example2 = registerExample(&Example{
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
					Services: []string{anyStr},
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
					Services: []string{anyStr},
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
					Services: []string{anyStr},
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
					Services: []string{anyStr},
					Action:   JumpToApp,
				},
				{
					Name:     "allow-Dumbledore-to-Gryffindor",
					ID:       10217,
					Source:   "Dumbledore",
					Dest:     "Gryffindor",
					Services: []string{anyStr},
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
					Services: []string{anyStr},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-Client-Access",
					ID:       9195,
					Source:   anyStr,
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
					Source:   anyStr,
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
					Source:   anyStr,
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
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var Example3 = registerExample(example3FromExample2())

func example3FromExample2() *Example {
	res := *Example2

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
	return &res
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ExampleDumbeldore
// Dumbledore1 can communicate to all
// Dumbledore2 can communicate to all but slytherin
var ExampleDumbeldore = registerExample(&Example{
	Name: "ExampleDumbeldore",
	VMs:  []string{huf, gry, dum1, dum2},
	GroupsByVMs: map[string][]string{
		sly:               {},
		huf:               {huf},
		gry:               {gry},
		dum:               {dum1, dum2},
		"DumbledoreAll":   {dum1},
		"DumbledoreNoSly": {dum2},
	},
	Policies: []Category{
		{
			Name:         "From-Dumbledore-connection",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "Dumb1-To-All",
					ID:       newRuleID,
					Source:   "DumbledoreAll",
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Allow,
				},
				{
					Name:     "Dumb2-Not-Sly",
					ID:       newRuleID + 1,
					Source:   "DumbledoreNoSly",
					Dest:     sly,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "Dumb2-To-All",
					ID:       newRuleID + 2,
					Source:   "DumbledoreNoSly",
					Dest:     anyStr,
					Services: []string{anyStr},
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
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ExampleTwoDeniesSimple
// Simple example with two denies
// Slytherin can talk to all but Dumbledore
// Gryffindor can talk to all but Dumbledore
var ExampleTwoDeniesSimple = registerExample(&Example{
	Name: "ExampleTwoDeniesSimple",
	VMs:  []string{sly, huf, gry, dum2},
	GroupsByVMs: map[string][]string{
		sly:  {sly},
		huf:  {huf},
		gry:  {gry},
		dum:  {dum2},
		dum1: {},
		dum2: {dum2},
	},
	Policies: []Category{
		{
			Name:         "Two-Denys-Simple-Test",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "no-conn-to-dumb1",
					ID:       1,
					Source:   anyStr,
					Dest:     dum1,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "no-conn-to-dumb2",
					ID:       2,
					Source:   anyStr,
					Dest:     dum2,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "Slytherin-to-all",
					ID:       3,
					Source:   sly,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-to-all",
					ID:       4,
					Source:   gry,
					Dest:     anyStr,
					Services: []string{anyStr},
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
	DisjointGroupsTags: [][]string{
		{sly, huf, gry, dum1, dum2},
	},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var disjointHouses2Dum = [][]string{{sly, huf, gry, dum, dum1, dum2}}

// ExampleDenyPassSimple one pass and two denies, span over two categories
// all can talk to all but Slytherin and Hufflepuff (or to Gryffindor and Dumbledore)
var ExampleDenyPassSimple = registerExample(&Example{
	Name: "ExampleDenyPassSimple",
	VMs:  []string{sly, huf, gry, dum1, dum2},
	GroupsByVMs: map[string][]string{
		sly:  {sly},
		huf:  {huf},
		gry:  {gry},
		dum:  {dum1, dum2},
		dum1: {dum1},
		dum2: {dum2},
	},
	Policies: []Category{
		{
			Name:         "Env-pass-and-deny",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:     "pass-all-to-dumb",
					ID:       newRuleID,
					Source:   anyStr,
					Dest:     dum,
					Services: []string{anyStr},
					Action:   JumpToApp,
				},
				{
					Name:     "deny-all-to-Hufflepuff",
					ID:       newRuleID + 1,
					Source:   anyStr,
					Dest:     huf,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "deny-all-to-Slytherin",
					ID:       newRuleID + 2,
					Source:   anyStr,
					Dest:     sly,
					Services: []string{anyStr},
					Action:   Drop,
				},
			},
		},
		{
			Name:         "App-Allow-All",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "allow-all-to-all",
					ID:       newRuleID + 3,
					Source:   anyStr,
					Dest:     anyStr,
					Services: []string{anyStr},
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
	DisjointGroupsTags: disjointHouses2Dum,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ExampleHintsDisjoint for testing the hint of disjoint groups/tags and relevant optimization
// Dumbledore1 can talk to all but Slytherin
// Dumbledore2 can talk to all but Gryffindor
var ExampleHintsDisjoint = registerExample(&Example{
	Name: "ExampleHintsDisjoint",
	VMs:  []string{sly, huf, gry, dum1, dum2},
	GroupsByVMs: map[string][]string{
		sly:  {sly},
		huf:  {huf},
		gry:  {gry},
		dum1: {dum1},
		dum2: {dum2},
	},
	Policies: []Category{
		{
			Name:         "From-Dumbledore-connection",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "Dumb1-Not-Sly",
					ID:       newRuleID,
					Source:   dum1,
					Dest:     sly,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "Dumb2-Not-Gryf",
					ID:       newRuleID + 1,
					Source:   dum2,
					Dest:     gry,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "Dumb1-To-All",
					ID:       newRuleID + 2,
					Source:   dum1,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Allow,
				},
				{
					Name:     "Dumb2-To-All",
					ID:       newRuleID + 3,
					Source:   dum2,
					Dest:     anyStr,
					Services: []string{anyStr},
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
	DisjointGroupsTags: disjointHouses2Dum,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

var hogwartsBidimensionalGroups = map[string][]string{
	sly: {slyWeb, slyApp, slyDB},
	huf: {hufWeb, hufApp, hufDB},
	gry: {gryWeb, gryApp, gryDB},
	dum: {dum1, dum2},
	web: {slyWeb, gryWeb, hufWeb},
	app: {slyApp, gryApp, hufApp},
	db:  {slyDB, gryDB, hufDB}}

var ExampleHogwarts = registerExample(&Example{
	Name: "ExampleHogwarts",
	VMs: []string{slyWeb, slyApp, slyDB, hufWeb, hufApp, hufDB,
		gryWeb, gryApp, gryDB, dum1, dum2},
	GroupsByVMs: hogwartsBidimensionalGroups,
	Policies: []Category{
		{
			Name:         "Gryffindor-to-Gryffindor-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:   "allow-Gryffindor-to-Gryffindor",
					ID:     10218,
					Source: gry,
					Dest:   gry,
					Action: JumpToApp,
					Conn:   netset.AllTCPTransport(),
				},
			},
		},
		{
			Name:         "Hufflepuff-to-Hufflepuff-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:   "allow-Hufflepuff-to-Hufflepuff",
					ID:     10219,
					Source: huf,
					Dest:   huf,
					Action: JumpToApp,
					//nolint:mnd // these are the port numbers for the test
					Conn:      netset.NewUDPTransport(netp.MinPort, netp.MinPort, 300, 320),
					Direction: string(nsx.RuleDirectionIN),
				},
			},
		},
		{
			Name:         "Slytherin-to-Slytherin-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:     "allow-Slytherin-to-Slytherin",
					ID:       10220,
					Source:   sly,
					Dest:     sly,
					Services: []string{anyStr},
					Action:   JumpToApp,
				},
			},
		},
		{
			Name:         "Dumbledore-connection",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:     "allow-Dumbledore-to-all",
					ID:       10221,
					Source:   dum,
					Dest:     gry,
					Services: []string{anyStr},
					Action:   JumpToApp,
				},
				{
					Name:     "default-deny-env",
					ID:       10300,
					Source:   anyStr,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Drop,
				},
			},
		},

		{
			Name:         "Intra-App-Policy",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "Client-Access",
					ID:       10400,
					Source:   anyStr,
					Dest:     web,
					Services: []string{anyStr},
					Action:   Allow,
				},
				{
					Name:     "Web-To-App-Access",
					ID:       10401,
					Source:   web,
					Dest:     app,
					Services: []string{anyStr},
					Action:   Allow,
				},
				{
					Name:     "App-To-DB-Access",
					ID:       10405,
					Source:   app,
					Dest:     db,
					Services: []string{anyStr},
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
	DisjointGroupsTags: [][]string{
		{sly, huf, gry, dum},
		{web, app, db},
		{web, dum},
		{app, dum},
		{db, dum},
	},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var disjointHousesAndFunctionality = [][]string{
	{sly, huf, gry, dum},
	{web, app, db}}

var simpleHogwartsGroups = map[string][]string{
	sly: {slyWeb, slyApp},
	gry: {gryWeb, gryApp},
	web: {slyWeb, gryWeb},
	app: {slyApp, gryApp}}

var ExampleHogwartsSimpler = registerExample(&Example{
	Name: "ExampleHogwartsSimpler",
	VMs: []string{slyWeb, slyApp, slyDB,
		gryWeb, gryApp, gryDB},
	GroupsByVMs: simpleHogwartsGroups,
	Policies: []Category{
		{
			Name:         "Gryffindor-to-Gryffindor-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:   "allow-Gryffindor-to-Gryffindor",
					ID:     10218,
					Source: gry,
					Dest:   gry,
					Action: JumpToApp,
					Conn:   netset.AllTCPTransport(),
				},
			},
		},
		{
			Name:         "Slytherin-to-Slytherin-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:   "allow-Slytherin-to-Slytherin",
					ID:     10220,
					Source: sly,
					Dest:   sly,
					Action: JumpToApp,
					Conn:   netset.AllUDPTransport().Union(netset.AllTCPTransport()),
				},
				{
					Name:     "default-deny-env",
					ID:       10221,
					Source:   anyStr,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Drop,
				},
			},
		},
		{
			Name:         "Intra-App-Policy",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:   "Client-Access",
					ID:     9195,
					Source: anyStr,
					Dest:   web,
					Action: Allow,
					Conn:   netset.AllTCPTransport(),
				},
				{
					Name:   "Web-To-App-Access",
					ID:     9196,
					Source: web,
					Dest:   app,
					Action: Allow,
					Conn:   netset.AllUDPTransport(),
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var hogwartsAppToHousesPolicy = []Category{
	{
		Name:         "Gryffindor-to-Gryffindor-allow",
		CategoryType: environment,
		Rules: []Rule{
			{
				Name:     "allow-Gryffindor-to-Gryffindor",
				ID:       10218,
				Source:   gry,
				Dest:     gry,
				Services: []string{anyStr},
				Action:   JumpToApp,
			},
		},
	},
	{
		Name:         "Hufflepuff-to-Hufflepuff-allow",
		CategoryType: environment,
		Rules: []Rule{
			{
				Name:     "allow-Hufflepuff-to-Hufflepuff",
				ID:       10219,
				Source:   huf,
				Dest:     huf,
				Services: []string{anyStr},
				Action:   JumpToApp,
			},
		},
	},
	{
		Name:         "Slytherin-to-Slytherin-allow",
		CategoryType: environment,
		Rules: []Rule{
			{
				Name:     "allow-Slytherin-to-Slytherin",
				ID:       10220,
				Source:   sly,
				Dest:     sly,
				Services: []string{anyStr},
				Action:   JumpToApp,
			},
			{
				Name:     "default-deny-env",
				ID:       10230,
				Source:   anyStr,
				Dest:     anyStr,
				Services: []string{anyStr},
				Action:   Drop,
			},
		},
	},
	{
		Name:         "Intra-App-Policy",
		CategoryType: application,
		Rules: []Rule{
			{
				Name:     "Client-Access",
				ID:       9195,
				Source:   anyStr,
				Dest:     web,
				Services: []string{anyStr},
				Action:   Allow,
			},
			{
				Name:     "Web-To-App-Access",
				ID:       9196,
				Source:   web,
				Dest:     app,
				Services: []string{anyStr},
				Action:   Allow,
			},
			{
				Name:     "App-To-DB-Access",
				ID:       9197,
				Source:   app,
				Dest:     db,
				Services: []string{anyStr},
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
}

var ExampleHogwartsNoDumbledore = registerExample(&Example{
	Name: "ExampleHogwartsNoDumbledore",
	VMs: []string{slyWeb, slyApp, slyDB, hufWeb, hufApp, hufDB,
		gryWeb, gryApp, gryDB},
	GroupsByVMs: map[string][]string{
		sly: {slyWeb, slyApp, slyDB},
		huf: {hufWeb, hufApp, hufDB},
		gry: {gryWeb, gryApp, gryDB},
		web: {slyWeb, gryWeb, hufWeb},
		app: {slyApp, gryApp, hufApp},
		db:  {slyDB, gryDB, hufDB},
	},
	Policies:           hogwartsAppToHousesPolicy,
	DisjointGroupsTags: disjointHousesAndFunctionality,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// examples with expr instead of direct vms references

var disjointHouses = [][]string{{sly, huf, gry, dum}}

var ExampleExprSingleScope = registerExample(&Example{
	Name:    "ExampleExprSingleScope",
	VMs:     []string{huf, gry, dum},
	VMsTags: map[string][]nsx.Tag{huf: {{Tag: huf}}, gry: {{Tag: gry}}, dum: {{Tag: dum}}},
	GroupsByExpr: map[string]ExampleExpr{
		sly: {Cond1: ExampleCond{Tag: nsx.Tag{Tag: sly}}},
		gry: {Cond1: ExampleCond{Tag: nsx.Tag{Tag: gry}}},
		huf: {Cond1: ExampleCond{Tag: nsx.Tag{Tag: huf}}},
		dum: {Cond1: ExampleCond{Tag: nsx.Tag{Tag: dum}}}},
	Policies: []Category{
		{
			Name:         "From-Dumbledore-connection",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "Dumb-No-Slytherin",
					ID:       newRuleID,
					Source:   dum,
					Dest:     sly,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "Dumb-All",
					ID:       newRuleID + 1,
					Source:   dum,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Allow,
				},
			},
		},
		{
			Name:         "Gryffindor-connections",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "Gryffindor-not-Hufflepuff",
					ID:       newRuleID + 2,
					Source:   gry,
					Dest:     huf,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "Gryffindor-All",
					ID:       newRuleID + 3,
					Source:   gry,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Allow,
				},
			},
		},
		{
			Name:         "Hufflepuff-connection",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "Hufflepuff-No-Slytherin",
					ID:       newRuleID + 4,
					Source:   huf,
					Dest:     sly,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "Hufflepuff-All",
					ID:       newRuleID + 5,
					Source:   huf,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Allow,
				},
			},
		},
		{
			Name:         "Slytherin-connection",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "Slytherin-no-Gryffindor",
					ID:       newRuleID + 6,
					Source:   sly,
					Dest:     gry,
					Services: []string{anyStr},
					Action:   Drop,
				},
				{
					Name:     "Slytherin-All",
					ID:       newRuleID + 7,
					Source:   sly,
					Dest:     anyStr,
					Services: []string{anyStr},
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
	DisjointGroupsTags: disjointHouses,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var vmsHousesTags = map[string][]nsx.Tag{slyDB: {{Scope: house, Tag: sly}, {Scope: funct, Tag: db}},
	slyWeb: {{Scope: house, Tag: sly}, {Scope: funct, Tag: web}},
	slyApp: {{Scope: house, Tag: sly}, {Scope: funct, Tag: app}},
	hufDB:  {{Scope: house, Tag: huf}, {Scope: funct, Tag: db}},
	hufWeb: {{Scope: house, Tag: huf}, {Scope: funct, Tag: web}},
	hufApp: {{Scope: house, Tag: huf}, {Scope: funct, Tag: app}},
	gryDB:  {{Scope: house, Tag: gry}, {Scope: funct, Tag: db}},
	gryWeb: {{Scope: house, Tag: gry}, {Scope: funct, Tag: web}},
	gryApp: {{Scope: house, Tag: gry}, {Scope: funct, Tag: app}}}

var twoScopeGroupsByExpr = map[string]ExampleExpr{
	sly: {Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}},
	gry: {Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}},
	huf: {Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}},
	db:  {Cond1: ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}}},
	web: {Cond1: ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: web}}},
	app: {Cond1: ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: app}}}}

var ExampleExprTwoScopes = registerExample(&Example{
	Name: "ExampleExprTwoScopes",
	VMs: []string{slyDB, slyWeb, slyApp,
		hufDB, hufWeb, hufApp,
		gryDB, gryWeb, gryApp},
	VMsTags:            vmsHousesTags,
	GroupsByExpr:       twoScopeGroupsByExpr,
	Policies:           hogwartsAppToHousesPolicy,
	DisjointGroupsTags: disjointHousesAndFunctionality,
})

// ExampleExprTwoScopesAbstract is like ExampleExprTwoScopes expect it has no VMs
var ExampleExprTwoScopesAbstract = registerExample(&Example{
	Name:               "ExampleExprTwoScopesAbstract",
	VMs:                []string{},
	VMsTags:            map[string][]nsx.Tag{},
	GroupsByExpr:       twoScopeGroupsByExpr,
	Policies:           hogwartsAppToHousesPolicy,
	DisjointGroupsTags: disjointHousesAndFunctionality,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var vmsHouses = []string{slyDB, slyWeb, slyApp,
	hufDB, hufWeb, hufApp,
	gryDB, gryWeb, gryApp}

// ExampleExprAndConds todo: this example uses not yet supported scope
var ExampleExprAndConds = registerExample(&Example{
	Name:               "ExampleExprAndConds",
	VMs:                vmsHouses,
	VMsTags:            vmsHousesTags,
	GroupsByExpr:       getAndOrOrExpr(And),
	Policies:           getAndOrOrPolicies(And),
	DisjointGroupsTags: disjointHousesAndFunctionality,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ExampleExprOrConds todo: this example uses not yet supported scope
var ExampleExprOrConds = registerExample(&Example{
	Name:               "ExampleExprOrConds",
	VMs:                vmsHouses,
	VMsTags:            vmsHousesTags,
	GroupsByExpr:       getAndOrOrExpr(Or),
	Policies:           getAndOrOrPolicies(Or),
	DisjointGroupsTags: disjointHousesAndFunctionality,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

const (
	slyAndNoDB = "Slytherin-And-no-DB"
	hufAndNoDB = "Hufflepuff-And-no-DB"
	gryAndNoDB = "Gryffindor-And-no-DB"
	slyOrNoDB  = "Slytherin-Or-no-DB"
	hufOrNoDB  = "Hufflepuff-Or-no-DB"
	gryOrNoDB  = "Gryffindor-Or-no-DB"
)

func getAndOrOrExpr(op ExampleOp) map[string]ExampleExpr {
	slyCondDB, hufCondDB, gryCondDB := getOrOrAnsGroupNames(op)
	slyAndOrDBExpr := ExampleExpr{Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}, Op: op,
		Cond2: ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}}
	hufAndOrDBExpr := ExampleExpr{Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}, Op: op,
		Cond2: ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}}
	gryAndOrDBExpr := ExampleExpr{Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}, Op: op,
		Cond2: ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}}
	return map[string]ExampleExpr{
		sly:       {Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}},
		gry:       {Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}},
		huf:       {Cond1: ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}},
		slyCondDB: slyAndOrDBExpr,
		hufCondDB: hufAndOrDBExpr,
		gryCondDB: gryAndOrDBExpr,
	}
}

func getOrOrAnsGroupNames(op ExampleOp) (slyDB, hufDB, gryDB string) {
	slyDB = slyAndNoDB
	hufDB = hufAndNoDB
	gryDB = gryAndNoDB
	if op == Or {
		slyDB = slyOrNoDB
		hufDB = hufOrNoDB
		gryDB = gryOrNoDB
	}
	return
}

func getAndOrOrPolicies(op ExampleOp) []Category {
	slyCondDB, hufCondDB, gryCondDB := getOrOrAnsGroupNames(op)
	return []Category{
		{
			Name:         "Protect-DBs",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:      "to-Slytherin-in",
					ID:        newRuleID,
					Source:    anyStr,
					Dest:      slyCondDB,
					Services:  []string{anyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "to-Slytherin-out",
					ID:        newRuleID + 1,
					Source:    gry,
					Dest:      slyCondDB,
					Services:  []string{anyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "to-Gryffindor-in",
					ID:        newRuleID + 2,
					Source:    anyStr,
					Dest:      gryCondDB,
					Services:  []string{anyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name: "to-Hufflepuff-out",
					//nolint:all // this is the required id
					ID:        newRuleID + 3,
					Source:    anyStr,
					Dest:      hufCondDB,
					Services:  []string{anyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name: "default-deny-env",
					//nolint:all // this is the required id
					ID:       10300,
					Source:   anyStr,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Drop,
				},
			},
		},
	}
}

var ExampleHogwartsSimplerNonSymInOut = registerExample(&Example{
	Name: "ExampleHogwartsSimplerNonSymInOut",
	VMs: []string{slyWeb, slyApp, slyDB,
		gryWeb, gryApp, gryDB},
	GroupsByVMs: simpleHogwartsGroups,
	Policies: []Category{
		{
			Name:         "Gryffindor-to-Gryffindor-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:      "allow-Gryffindor-to-Gryffindor-in",
					ID:        10218,
					Source:    gry,
					Dest:      gry,
					Action:    JumpToApp,
					Conn:      netset.AllTransports(),
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow-Gryffindor-to-Gryffindor-out",
					ID:        10219,
					Source:    gry,
					Dest:      gry,
					Action:    JumpToApp,
					Conn:      netset.AllTCPTransport(),
					Direction: string(nsx.RuleDirectionOUT),
				},
			},
		},
		{
			Name:         "Slytherin-to-Slytherin-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:      "allow-Slytherin-to-Slytherin-in",
					ID:        10220,
					Source:    sly,
					Dest:      sly,
					Action:    JumpToApp,
					Conn:      netset.AllUDPTransport().Union(netset.AllTCPTransport()),
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow-Slytherin-to-Slytherin-out",
					ID:        10221,
					Source:    sly,
					Dest:      sly,
					Action:    JumpToApp,
					Conn:      netset.AllUDPTransport(),
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:     "default-deny-env",
					ID:       10231,
					Source:   anyStr,
					Dest:     anyStr,
					Services: []string{anyStr},
					Action:   Drop,
				},
			},
		},
		{
			Name:         "Intra-App-Policy",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:      "Client-Access-in",
					ID:        11000,
					Source:    anyStr,
					Dest:      web,
					Action:    Allow,
					Conn:      netset.AllTransports(),
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "Client-Access-out",
					ID:        11001,
					Source:    anyStr,
					Dest:      web,
					Action:    Allow,
					Conn:      netset.AllUDPTransport().Union(netset.AllTCPTransport()),
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "Web-To-App-Access-in",
					ID:        11002,
					Source:    web,
					Dest:      app,
					Action:    Allow,
					Conn:      netset.AllUDPTransport().Union(netset.AllTCPTransport()),
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "Web-To-App-Access-out",
					ID:        11004,
					Source:    web,
					Dest:      app,
					Action:    Allow,
					Conn:      netset.AllTCPTransport(),
					Direction: string(nsx.RuleDirectionOUT),
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var ExampleHogwartsExternal = registerExample(&Example{
	Name: "ExampleHogwartsOut",
	VMs: []string{slyWeb, slyApp, slyDB, hufWeb, hufApp, hufDB,
		gryWeb, gryApp, gryDB, dum1, dum2},
	GroupsByVMs: hogwartsBidimensionalGroups,
	Policies: []Category{
		{
			Name:         "Gryffindor-to-External-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:      "allow-Gryffindor-to-External",
					ID:        10218,
					Source:    gry,
					Dest:      "0.0.0.0/0",
					Action:    JumpToApp,
					Conn:      netset.AllTCPTransport(),
					Direction: string(nsx.RuleDirectionOUT),
				},
			},
		},
		{
			Name:         "Hufflepuff-to-External-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:   "allow-Hufflepuff-to-External",
					ID:     10219,
					Source: huf,
					Dest:   "0.0.0.0/0",
					Action: JumpToApp,
					//nolint:mnd // these are the port numbers for the test
					Conn:      netset.NewUDPTransport(netp.MinPort, netp.MinPort, 300, 320),
					Direction: string(nsx.RuleDirectionOUT),
				},
			},
		},
		{
			Name:         "Slytherin-to-External-allow",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:      "allow-Slytherin-to-External",
					ID:        10220,
					Source:    sly,
					Dest:      "0.0.0.0/0",
					Services:  []string{anyStr},
					Action:    JumpToApp,
					Direction: string(nsx.RuleDirectionOUT),
				},
			},
		},
		{
			Name:         "Dumbledore-connection",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:      "allow-all-to-dumb-Dumbledore",
					ID:        10221,
					Source:    "0.0.0.0/0",
					Dest:      dum,
					Services:  []string{anyStr},
					Direction: string(nsx.RuleDirectionIN),
					Action:    JumpToApp,
				},
				{
					Name:     "default-deny-env",
					ID:       10300,
					Source:   anyStr,
					Dest:     "0.0.0.0/0",
					Services: []string{anyStr},
					Action:   Drop,
				},
			},
		},

		{
			Name:         "Web-to-external",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:      "Client-Access",
					ID:        10400,
					Source:    web,
					Dest:      "0.0.1.0/16",
					Services:  []string{anyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "App-to-external",
					ID:        10401,
					Source:    app,
					Dest:      "146.2.0.0/16",
					Services:  []string{anyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "DB-to-external",
					ID:        10405,
					Source:    db,
					Dest:      "220.0.1.0/28",
					Services:  []string{anyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "to-Dumb",
					ID:        10406,
					Source:    "122.0.0.0/8",
					Dest:      dum,
					Services:  []string{anyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
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
	DisjointGroupsTags: [][]string{
		{sly, huf, gry, dum},
		{web, app, db},
		{web, dum},
		{app, dum},
		{db, dum},
	},
})
