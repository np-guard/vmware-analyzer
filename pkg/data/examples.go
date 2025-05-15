package data

import (
	"slices"

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
	sly    = "Slytherin"
	huf    = "Hufflepuff"
	gry    = "Gryffindor"
	dum    = "Dumbledore"
	Dum1   = "Dumbledore1"
	Dum2   = "Dumbledore2"
	notSly = "Not Slytherin"

	house = "House"
	funct = "Function"
	db    = "DB"
	app   = "App"
	web   = "Web"

	slyDB  = "Slytherin-DB"
	slyApp = "Slytherin-App"
	SlyWeb = "Slytherin-Web"
	gryDB  = "Gryffindor-DB"
	gryApp = "Gryffindor-App"
	GryWeb = "Gryffindor-Web"
	hufDB  = "Hufflepuff-DB"
	hufApp = "Hufflepuff-App"
	HufWeb = "Hufflepuff-Web"
)

const (
	application = "Application"
	environment = "Environment"
	defaultL3   = "Default-L3-Section"

	frontEnd = "frontend"
	backEnd  = "backend"
	aladdin  = "Aladdin"
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
					Services: []string{AnyStr},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var Example1aRedundantRuleInOut = registerExample(&Example{
	Name: "Example1aRedundantRuleInOut",
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
					Name:     "allow_smb_incoming",
					ID:       1006,
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
					Services: []string{AnyStr},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var Example1aRedundantRuleIn = registerExample(&Example{
	Name: "Example1aRedundantRuleIn",
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
					Name:      "allow_smb_incoming",
					ID:        1006,
					Source:    frontEnd,
					Dest:      backEnd,
					Services:  []string{"/infra/services/SMB"},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:     "allow_all_frontend_to_backend",
					ID:       1005,
					Source:   frontEnd,
					Dest:     backEnd,
					Services: []string{AnyStr},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var Example1aRedundantRuleOut = registerExample(&Example{
	Name: "Example1aRedundantRuleOut",
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
					Name:      "allow_smb_incoming",
					ID:        1004,
					Source:    frontEnd,
					Dest:      backEnd,
					Services:  []string{"/infra/services/SMB"},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:     "allow_smb_incoming",
					ID:       1006,
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
					Services: []string{AnyStr},
					Action:   Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var Example1aRedundantRuleOutInSeparated = registerExample(&Example{
	Name: "Example1aRedundantRuleOutInSeparated",
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
					Name:      "allow_smb_incoming",
					ID:        1004,
					Source:    frontEnd,
					Dest:      backEnd,
					Services:  []string{"/infra/services/SMB"},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "allow_smb_incoming",
					ID:        1006,
					Source:    frontEnd,
					Dest:      backEnd,
					Services:  []string{"/infra/services/SMB"},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:     "allow_all_frontend_to_backend",
					ID:       1005,
					Source:   frontEnd,
					Dest:     backEnd,
					Services: []string{AnyStr},
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

// External IPs

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
		"frontend": {"A"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:      "deny_tcp_0_1",
					ID:        1004,
					Source:    "1.2.0.0/30",
					Dest:      AnyStr,
					Scope:     frontEnd,
					Conn:      netset.AllTCPTransport(),
					Direction: string(nsx.RuleDirectionIN),
					Action:    Drop,
				},
				{
					Name:      "allow_tcp_0_1",
					ID:        1005,
					Source:    "1.2.0.0-1.2.1.255",
					Dest:      AnyStr,
					Scope:     frontEnd,
					Conn:      netset.AllTCPTransport(),
					Direction: string(nsx.RuleDirectionIN),
					Action:    Allow,
				},
				{
					Name:      "allow_udp_3_4",
					ID:        1006,
					Source:    "1.2.3.0-1.2.4.255",
					Dest:      frontEnd,
					Conn:      netset.AllUDPTransport(),
					Direction: string(nsx.RuleDirectionIN),
					Action:    Allow,
				},
				{
					Name:      "allow_icmp_1_3",
					ID:        1007,
					Source:    "1.2.1.0-1.2.3.255",
					Dest:      frontEnd,
					Conn:      netset.AllICMPTransport(),
					Direction: string(nsx.RuleDirectionIN),
					Action:    Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

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
					Dest:      AnyStr,
					Scope:     frontEnd,
					Conn:      netset.AllTCPTransport(),
					Action:    Drop,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow_tcp_0_1",
					ID:        1005,
					Source:    "1.2.0.0/24",
					Dest:      frontEnd,
					Scope:     AnyStr,
					Conn:      netset.AllTCPTransport(),
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "deny_all_conn_0_1",
					ID:        1006,
					Source:    "1.2.0.0/24",
					Dest:      AnyStr,
					Scope:     frontEnd,
					Conn:      netset.AllTransports(),
					Action:    Drop,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow_all_conn_0_1",
					ID:        1007,
					Source:    "1.2.0.0/16",
					Dest:      frontEnd,
					Scope:     AnyStr,
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
					Dest:      AnyStr,
					Scope:     frontEnd,
					Conn:      netset.AllTCPTransport(),
					Action:    Drop,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow_all_conn_0_2",
					ID:        1009,
					Source:    "1.240.0.0/28",
					Dest:      frontEnd,
					Scope:     AnyStr,
					Conn:      netset.AllTransports(),
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

var vms = []string{"vm1", "vm2", "vm3", "vm4", "vm5", "vm6", "vm7", "vm8", "vm9", "vm10", "vm-no-address1", "vm-no-address2"}
var groupsInternalWithInterDenyAllow = map[string][]string{"default-group": {"vm1", "vm2", "vm3", "vm4", "vm5",
	"vm6", "vm7", "vm8", "vm9", "vm10"}, "real-group": {"vm-no-address1", "vm-no-address2"}}
var vmsAddresses = map[string]string{
	"vm1":  "10.0.0.2",
	"vm2":  "10.0.0.100",
	"vm3":  "10.0.0.101",
	"vm4":  "10.0.1.0",
	"vm5":  "10.0.1.1",
	"vm6":  "10.250.1.0",
	"vm7":  "10.250.1.1",
	"vm8":  "172.16.10.10",
	"vm9":  "192.168.0.0",
	"vm10": "192.168.255.0",
}
var policiesInternalWithInterDenyAllow = []Category{
	{
		Name:         "app-x",
		CategoryType: "Application",
		Rules: []Rule{
			{
				Name:   "deny1",
				ID:     1004,
				Source: "10.0.0.0/30",
				Dest:   "0.0.0.0/0",
				Action: Drop,
				Conn:   netset.AllTransports(),
			},
			{
				Name:   "allow1",
				ID:     1005,
				Source: "10.0.0.0/24",
				Dest:   "0.0.0.0/0",
				Action: Allow,
				Conn:   netset.AllTransports(),
			},
			{
				Name:   "deny2",
				ID:     1006,
				Source: "10.0.0.0/20",
				Dest:   "0.0.0.0/0",
				Action: Drop,
				Conn:   netset.AllTransports(),
			},
			{
				Name:   "allow2",
				ID:     1007,
				Source: "10.0.0.0/16",
				Dest:   "0.0.0.0/0",
				Action: Allow,
				Conn:   netset.AllTransports(),
			},
			{
				Name:   "drop-real-group",
				ID:     2000,
				Source: "172.16.10.10/16",
				Dest:   "real-group",
				Action: Drop,
				Conn:   netset.AllTransports(),
			},
			{
				Name:   "allow-all-after-drop-real-group",
				ID:     2200,
				Source: "172.16.10.10/16",
				Dest:   "0.0.0.0/0",
				Action: Allow,
				Conn:   netset.AllTransports(),
			},
			{
				Name:   "allow-only-2",
				ID:     3000,
				Source: "192.168.0.0/16",
				Dest:   "0.0.0.0/0",
				Action: Allow,
				Conn:   netset.AllTransports(),
			},
			{
				Name:   "allow-group",
				ID:     4008,
				Source: "real-group",
				Dest:   "real-group",
				Action: Allow,
				Conn:   netset.AllTransports(),
			},
			DefaultDenyRule(denyRuleIDApp),
		},
	},
}

var ExampleExternalWithTautology = registerExample(&Example{
	Name: "ExampleExternalWithTautology",
	VMs:  []string{"A"},
	GroupsByVMs: map[string][]string{
		"frontend": {"A"},
	},
	Policies: []Category{
		{
			Name:         "app-x",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:      "deny",
					ID:        1004,
					Source:    "1.0.0.0/24",
					Dest:      AnyStr,
					Conn:      netset.AllTransports(),
					Direction: string(nsx.RuleDirectionIN),
					Action:    Drop,
				},
				{
					Name:      "allow",
					ID:        1005,
					Source:    "0.0.0.0/0",
					Dest:      AnyStr,
					Conn:      netset.AllTransports(),
					Direction: string(nsx.RuleDirectionIN),
					Action:    Allow,
				},
				DefaultDenyRule(denyRuleIDApp),
			},
		},
	},
})

// Internal IPS

var ExampleInternalWithInterDenyAllow = registerExample(&Example{
	Name:        "ExampleInternalWithInterDenyAllow",
	VMs:         vms,
	GroupsByVMs: groupsInternalWithInterDenyAllow,
	VMsAddress:  vmsAddresses,
	Policies:    policiesInternalWithInterDenyAllow,
})

var ExampleInternalWithInterDenyAllowWithSegments = registerExample(&Example{
	Name:        "ExampleInternalWithInterDenyAllowWithSegments",
	VMs:         vms,
	GroupsByVMs: groupsInternalWithInterDenyAllow,
	VMsAddress:  vmsAddresses,
	SegmentsByVMs: map[string][]string{
		"seg_1":    {"vm1"},
		"seg_2-3":  {"vm2", "vm3"},
		"seg_4-5":  {"vm4", "vm5"},
		"seg-6-7":  {"vm6", "vm7"},
		"seg-8":    {"vm8"},
		"seg-9-10": {"vm9", "vm10"},
	},
	SegmentsBlock: map[string]string{
		"seg_1":    "10.0.0.0/30",
		"seg_2-3":  "10.0.0.0/24",
		"seg_4-5":  "10.0.0.0/20",
		"seg-6-7":  "10.0.0.0/16",
		"seg-8":    "172.16.10.10/16",
		"seg-9-10": "192.168.0.0/16",
	},
	Policies: policiesInternalWithInterDenyAllow,
})

// ExampleInternalWithInterDenyAllowMixedSegments todo see https://github.com/np-guard/vmware-analyzer/issues/379
var ExampleInternalWithInterDenyAllowMixedSegments = registerExample(&Example{
	Name:        "ExampleInternalWithInterDenyAllowMixedSegments",
	VMs:         vms,
	GroupsByVMs: groupsInternalWithInterDenyAllow,
	VMsAddress:  vmsAddresses,
	SegmentsByVMs: map[string][]string{
		"seg_2-3": {"vm1", "vm2", "vm3"},
		"seg_4-5": {"vm1", "vm2", "vm3", "vm4", "vm5"},
		"seg-6-7": {"vm1", "vm2", "vm3", "vm4", "vm5", "vm6", "vm7"},
	},
	SegmentsBlock: map[string]string{
		"seg_1":   "10.0.0.0/32",
		"seg_2-3": "10.0.0.0/25",
		"seg_4-5": "10.0.0.0/20",
		"seg-6-7": "10.0.0.0/15",
	},
	Policies: policiesInternalWithInterDenyAllow,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var ExampleExclude = registerExample(&Example{
	Name: "ExampleExclude",
	VMs: []string{"Slytherin1", "Slytherin2", "Hufflepuff1", "Hufflepuff2",
		"Gryffindor1", "Gryffindor2", Dum1, Dum2, aladdin},
	GroupsByVMs: map[string][]string{
		sly:     {"Slytherin1", "Slytherin2"},
		huf:     {"Hufflepuff1", "Hufflepuff2"},
		gry:     {"Gryffindor1", "Gryffindor2"},
		dum:     {Dum1, Dum2},
		aladdin: {aladdin},
	},
	Policies: []Category{
		{
			Name:         "AladdinTalks",
			CategoryType: "Environment",
			Rules: []Rule{
				{
					Name:                 "allow-Aladdin-to-others",
					ID:                   10218,
					Source:               aladdin,
					Dest:                 aladdin,
					DestinationsExcluded: true,
					Services:             []string{AnyStr},
					Action:               Allow,
				},
				{
					Name:            "allow-others-to-Aladdin",
					ID:              10219,
					Source:          aladdin,
					Dest:            aladdin,
					SourcesExcluded: true,
					Services:        []string{AnyStr},
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
	VMs: []string{SlyWeb, slyApp, slyDB, HufWeb, hufApp, hufDB,
		GryWeb, gryApp, gryDB, Dum1, Dum2},
	GroupsByVMs: map[string][]string{
		sly:    {SlyWeb, slyApp, slyDB},
		huf:    {HufWeb, hufApp, hufDB},
		gry:    {GryWeb, gryApp, gryDB},
		dum:    {Dum1, Dum2},
		SlyWeb: {SlyWeb},
		slyApp: {slyApp},
		slyDB:  {slyDB},
		GryWeb: {GryWeb},
		gryApp: {gryApp},
		gryDB:  {gryDB},
		HufWeb: {HufWeb},
		hufApp: {hufApp},
		hufDB:  {hufDB},
	},
	Policies: []Category{
		{
			Name:         "Gryffindor-to-Gryffindor-allow",
			CategoryType: "Environment",
			Rules: []Rule{
				{
					Name:     "allow-Gryffindor-to-Gryffindor",
					ID:       10218,
					Source:   gry,
					Dest:     gry,
					Services: []string{AnyStr},
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
					Source:   huf,
					Dest:     huf,
					Services: []string{AnyStr},
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
					Source:   sly,
					Dest:     sly,
					Services: []string{AnyStr},
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
					Source:   gry,
					Dest:     dum,
					Services: []string{AnyStr},
					Action:   JumpToApp,
				},
				{
					Name:     "allow-Dumbledore-to-Gryffindor",
					ID:       10217,
					Source:   dum,
					Dest:     gry,
					Services: []string{AnyStr},
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
					Source:   gryApp,
					Dest:     hufApp,
					Services: []string{AnyStr},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-Client-Access",
					ID:       9195,
					Source:   AnyStr,
					Dest:     GryWeb,
					Services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-Web-To-App-Access",
					ID:       9196,
					Source:   GryWeb,
					Dest:     gryApp,
					Services: []string{"/infra/services/Vmware-VC-WebAccess"},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-App-To-DB-Access",
					ID:       9197,
					Source:   gryApp,
					Dest:     gryDB,
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
					Source:   AnyStr,
					Dest:     SlyWeb,
					Services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					Action:   Allow,
				},
				{
					Name:     "Slytherin-Web-To-App-Access",
					ID:       3049,
					Source:   SlyWeb,
					Dest:     slyApp,
					Services: []string{"/infra/services/Vmware-VC-WebAccess"},
					Action:   Allow,
				},
				{
					Name:     "Slytherin-App-To-DB-Access",
					ID:       3050,
					Source:   slyApp,
					Dest:     slyDB,
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
					Source:   AnyStr,
					Dest:     HufWeb,
					Services: []string{"/infra/services/HTTP", "/infra/services/HTTPS"},
					Action:   Allow,
				},
				{
					Name:     "Hufflepuff-Web-To-App-Access",
					ID:       2049,
					Source:   HufWeb,
					Dest:     hufApp,
					Services: []string{"/infra/services/Vmware-VC-WebAccess"},
					Action:   Allow,
				},
				{
					Name:     "Hufflepuff-App-To-DB-Access",
					ID:       2050,
					Source:   hufApp,
					Dest:     hufDB,
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
				res.Policies[i].Rules[j].Dest = gryApp
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
	VMs:  []string{huf, gry, Dum1, Dum2},
	GroupsByVMs: map[string][]string{
		sly:               {},
		huf:               {huf},
		gry:               {gry},
		dum:               {Dum1, Dum2},
		"DumbledoreAll":   {Dum1},
		"DumbledoreNoSly": {Dum2},
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
					Dest:     AnyStr,
					Services: []string{AnyStr},
					Action:   Allow,
				},
				{
					Name:     "Dumb2-Not-Sly",
					ID:       newRuleID + 1,
					Source:   "DumbledoreNoSly",
					Dest:     sly,
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "Dumb2-To-All",
					ID:       newRuleID + 2,
					Source:   "DumbledoreNoSly",
					Dest:     AnyStr,
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
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ExampleTwoDeniesSimple
// Simple example with two denies
// Slytherin can talk to all but Dumbledore
// Gryffindor can talk to all but Dumbledore
var ExampleTwoDeniesSimple = registerExample(&Example{
	Name: "ExampleTwoDeniesSimple",
	VMs:  []string{sly, huf, gry, Dum2},
	GroupsByVMs: map[string][]string{
		sly:  {sly},
		huf:  {huf},
		gry:  {gry},
		dum:  {Dum2},
		Dum1: {},
		Dum2: {Dum2},
	},
	Policies: []Category{
		{
			Name:         "Two-Denys-Simple-Test",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:     "no-conn-to-dumb1",
					ID:       1,
					Source:   AnyStr,
					Dest:     Dum1,
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "no-conn-to-dumb2",
					ID:       2,
					Source:   AnyStr,
					Dest:     Dum2,
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "Slytherin-to-all",
					ID:       3,
					Source:   sly,
					Dest:     AnyStr,
					Services: []string{AnyStr},
					Action:   Allow,
				},
				{
					Name:     "Gryffindor-to-all",
					ID:       4,
					Source:   gry,
					Dest:     AnyStr,
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
	DisjointGroupsTags: [][]string{
		{sly, huf, gry, Dum1, Dum2},
	},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var disjointHouses2Dum = [][]string{{sly, huf, gry, dum, Dum1, Dum2}, {sly, notSly}}

// ExampleDenyPassSimple one pass and two denies, span over two categories
// all can talk to all but Slytherin and Hufflepuff (or to Gryffindor and Dumbledore)
var ExampleDenyPassSimple = registerExample(&Example{
	Name: "ExampleDenyPassSimple",
	VMs:  []string{sly, huf, gry, Dum1, Dum2},
	GroupsByVMs: map[string][]string{
		sly:  {sly},
		huf:  {huf},
		gry:  {gry},
		dum:  {Dum1, Dum2},
		Dum1: {Dum1},
		Dum2: {Dum2},
	},
	Policies: []Category{
		{
			Name:         "Env-pass-and-deny",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:     "pass-all-to-dumb",
					ID:       newRuleID,
					Source:   AnyStr,
					Dest:     dum,
					Services: []string{AnyStr},
					Action:   JumpToApp,
				},
				{
					Name:     "deny-all-to-Hufflepuff",
					ID:       newRuleID + 1,
					Source:   AnyStr,
					Dest:     huf,
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "deny-all-to-Slytherin",
					ID:       newRuleID + 2,
					Source:   AnyStr,
					Dest:     sly,
					Services: []string{AnyStr},
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
					Source:   AnyStr,
					Dest:     AnyStr,
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
	DisjointGroupsTags: disjointHouses2Dum,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ExampleHintsDisjoint for testing the hint of disjoint groups/tags and relevant optimization
// Dumbledore1 can talk to all but Slytherin
// Dumbledore2 can talk to all but Gryffindor
var ExampleHintsDisjoint = registerExample(&Example{
	Name: "ExampleHintsDisjoint",
	VMs:  []string{sly, huf, gry, Dum1, Dum2},
	GroupsByVMs: map[string][]string{
		sly:    {sly},
		huf:    {huf},
		gry:    {gry},
		Dum1:   {Dum1},
		Dum2:   {Dum2},
		notSly: {huf, gry, Dum1, Dum2},
	},
	Policies:           HintsDisjointPolicy,
	DisjointGroupsTags: disjointHouses2Dum,
})

var ExampleHintsDisjointNoGivenHints = registerExample(&Example{
	Name: "ExampleHintsDisjoint",
	VMs:  []string{sly, huf, gry, Dum1, Dum2},
	GroupsByVMs: map[string][]string{
		sly:    {sly},
		huf:    {huf},
		gry:    {gry},
		Dum1:   {Dum1},
		Dum2:   {Dum2},
		notSly: {huf, gry, Dum1, Dum2},
	},
	Policies: HintsDisjointPolicy,
})

var HintsDisjointPolicy = []Category{
	{
		Name:         "From-Dumbledore-connection",
		CategoryType: application,
		Rules: []Rule{
			{
				Name:                 "Dumb1-Not-Sly",
				ID:                   newRuleID,
				Source:               Dum1,
				Dest:                 notSly,
				DestinationsExcluded: true,
				Services:             []string{AnyStr},
				Action:               Drop,
			},
			{
				Name:     "Dumb2-Not-Gryf",
				ID:       newRuleID + 1,
				Source:   Dum2,
				Dest:     gry,
				Services: []string{AnyStr},
				Action:   Drop,
			},
			{
				Name:     "Dumb1-To-All",
				ID:       newRuleID + 2,
				Source:   Dum1,
				Dest:     AnyStr,
				Services: []string{AnyStr},
				Action:   Allow,
			},
			{
				Name:     "Dumb2-To-All",
				ID:       newRuleID + 3,
				Source:   Dum2,
				Dest:     AnyStr,
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
}

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
	sly: {SlyWeb, slyApp, slyDB},
	huf: {HufWeb, hufApp, hufDB},
	gry: {GryWeb, gryApp, gryDB},
	dum: {Dum1, Dum2},
	web: {SlyWeb, GryWeb, HufWeb},
	app: {slyApp, gryApp, hufApp},
	db:  {slyDB, gryDB, hufDB}}

var ExampleHogwarts = registerExample(&Example{
	Name:               "ExampleHogwarts",
	VMs:                ExampleHogwartsVMs,
	GroupsByVMs:        hogwartsBidimensionalGroups,
	Policies:           ExampleHogwartsPolicies,
	DisjointGroupsTags: ExampleHogwartsDisjointGroup,
})

var ExampleHogwartsVMs = []string{SlyWeb, slyApp, slyDB, HufWeb, hufApp, hufDB,
	GryWeb, gryApp, gryDB, Dum1, Dum2}

var ExampleHogwartsPolicies = []Category{
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
				Dest:   AnyStr,
				Scope:  huf,
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
				Services: []string{AnyStr},
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
				Services: []string{AnyStr},
				Action:   JumpToApp,
			},
			{
				Name:     "default-deny-env",
				ID:       10300,
				Source:   AnyStr,
				Dest:     AnyStr,
				Services: []string{AnyStr},
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
				Source:   AnyStr,
				Dest:     web,
				Services: []string{AnyStr},
				Action:   Allow,
			},
			{
				Name:     "Web-To-App-Access",
				ID:       10401,
				Source:   web,
				Dest:     app,
				Services: []string{AnyStr},
				Action:   Allow,
			},
			{
				Name:     "App-To-DB-Access",
				ID:       10405,
				Source:   app,
				Dest:     db,
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
}

var ExampleHogwartsDisjointGroup = [][]string{
	{sly, huf, gry, dum},
	{web, app, db},
	{web, dum},
	{app, dum},
	{db, dum},
}

var ExampleHogwartsNoGivenHints = registerExample(&Example{
	Name:        "ExampleHogwarts",
	VMs:         ExampleHogwartsVMs,
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
					Dest:   AnyStr,
					Scope:  huf,
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
					Services: []string{AnyStr},
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
					Services: []string{AnyStr},
					Action:   JumpToApp,
				},
				{
					Name:     "default-deny-env",
					ID:       10300,
					Source:   AnyStr,
					Dest:     AnyStr,
					Services: []string{AnyStr},
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
					Source:   AnyStr,
					Dest:     web,
					Services: []string{AnyStr},
					Action:   Allow,
				},
				{
					Name:     "Web-To-App-Access",
					ID:       10401,
					Source:   web,
					Dest:     app,
					Services: []string{AnyStr},
					Action:   Allow,
				},
				{
					Name:     "App-To-DB-Access",
					ID:       10405,
					Source:   app,
					Dest:     db,
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
	DisjointGroupsTags: [][]string{},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var disjointHousesAndFunctionality = [][]string{
	{sly, huf, gry, dum},
	{web, app, db}}

var simpleHogwartsGroups = map[string][]string{
	sly: {SlyWeb, slyApp},
	gry: {GryWeb, gryApp},
	web: {SlyWeb, GryWeb},
	app: {slyApp, gryApp}}

var ExampleHogwartsSimpler = registerExample(&Example{
	Name: "ExampleHogwartsSimpler",
	VMs: []string{SlyWeb, slyApp, slyDB,
		GryWeb, gryApp, gryDB},
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
					Source:   AnyStr,
					Dest:     AnyStr,
					Services: []string{AnyStr},
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
					Source: AnyStr,
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
				Services: []string{AnyStr},
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
				Services: []string{AnyStr},
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
				Services: []string{AnyStr},
				Action:   JumpToApp,
			},
			{
				Name:     "default-deny-env",
				ID:       10230,
				Source:   AnyStr,
				Dest:     AnyStr,
				Services: []string{AnyStr},
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
				Source:   AnyStr,
				Dest:     web,
				Services: []string{AnyStr},
				Action:   Allow,
			},
			{
				Name:     "Web-To-App-Access",
				ID:       9196,
				Source:   web,
				Dest:     app,
				Services: []string{AnyStr},
				Action:   Allow,
			},
			{
				Name:     "App-To-DB-Access",
				ID:       9197,
				Source:   app,
				Dest:     db,
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
}

var ExampleHogwartsNoDumbledore = registerExample(&Example{
	Name: "ExampleHogwartsNoDumbledore",
	VMs: []string{SlyWeb, slyApp, slyDB, HufWeb, hufApp, hufDB,
		GryWeb, gryApp, gryDB},
	GroupsByVMs: map[string][]string{
		sly: {SlyWeb, slyApp, slyDB},
		huf: {HufWeb, hufApp, hufDB},
		gry: {GryWeb, gryApp, gryDB},
		web: {SlyWeb, GryWeb, HufWeb},
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
		sly: {Cond1: &ExampleCond{Tag: nsx.Tag{Tag: sly}}},
		gry: {Cond1: &ExampleCond{Tag: nsx.Tag{Tag: gry}}},
		huf: {Cond1: &ExampleCond{Tag: nsx.Tag{Tag: huf}}},
		dum: {Cond1: &ExampleCond{Tag: nsx.Tag{Tag: dum}}}},
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
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "Dumb-All",
					ID:       newRuleID + 1,
					Source:   dum,
					Dest:     AnyStr,
					Services: []string{AnyStr},
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
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "Gryffindor-All",
					ID:       newRuleID + 3,
					Source:   gry,
					Dest:     AnyStr,
					Services: []string{AnyStr},
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
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "Hufflepuff-All",
					ID:       newRuleID + 5,
					Source:   huf,
					Dest:     AnyStr,
					Services: []string{AnyStr},
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
					Services: []string{AnyStr},
					Action:   Drop,
				},
				{
					Name:     "Slytherin-All",
					ID:       newRuleID + 7,
					Source:   sly,
					Dest:     AnyStr,
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
	DisjointGroupsTags: disjointHouses,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var vmsHousesTags = map[string][]nsx.Tag{slyDB: {{Scope: house, Tag: sly}, {Scope: funct, Tag: db}},
	SlyWeb: {{Scope: house, Tag: sly}, {Scope: funct, Tag: web}},
	slyApp: {{Scope: house, Tag: sly}, {Scope: funct, Tag: app}},
	hufDB:  {{Scope: house, Tag: huf}, {Scope: funct, Tag: db}},
	HufWeb: {{Scope: house, Tag: huf}, {Scope: funct, Tag: web}},
	hufApp: {{Scope: house, Tag: huf}, {Scope: funct, Tag: app}},
	gryDB:  {{Scope: house, Tag: gry}, {Scope: funct, Tag: db}},
	GryWeb: {{Scope: house, Tag: gry}, {Scope: funct, Tag: web}},
	gryApp: {{Scope: house, Tag: gry}, {Scope: funct, Tag: app}}}

var twoScopeGroupsByExpr = map[string]ExampleExpr{
	sly: {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}},
	gry: {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}},
	huf: {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}},
	db:  {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}}},
	web: {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: web}}},
	app: {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: app}}}}

var ExampleExprTwoScopes = registerExample(&Example{
	Name: "ExampleExprTwoScopes",
	VMs: []string{slyDB, SlyWeb, slyApp,
		hufDB, HufWeb, hufApp,
		gryDB, GryWeb, gryApp},
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

var vmsHouses = []string{slyDB, SlyWeb, slyApp,
	hufDB, HufWeb, hufApp,
	gryDB, GryWeb, gryApp}

// ExampleExprAndConds todo: this example uses not yet supported scope
var ExampleExprAndConds = registerExample(&Example{
	Name:               "ExampleExprAndConds",
	VMs:                vmsHouses,
	VMsTags:            vmsHousesTags,
	GroupsByExpr:       getAndOrOrExpr(And),
	Policies:           getAndOrOrPolicies(And, false),
	DisjointGroupsTags: disjointHousesAndFunctionality,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ExampleExprOrConds todo: this example uses not yet supported scope
var ExampleExprOrConds = registerExample(&Example{
	Name:               "ExampleExprOrConds",
	VMs:                vmsHouses,
	VMsTags:            vmsHousesTags,
	GroupsByExpr:       getAndOrOrExpr(Or),
	Policies:           getAndOrOrPolicies(Or, false),
	DisjointGroupsTags: disjointHousesAndFunctionality,
})

// same examples with exclude - on expr

var ExampleExprAndCondsExclude = registerExample(&Example{
	Name:               "ExampleExprAndCondsExclude",
	VMs:                vmsHouses,
	VMsTags:            vmsHousesTags,
	GroupsByExpr:       getAndOrOrExpr(And),
	Policies:           getAndOrOrPolicies(And, true),
	DisjointGroupsTags: disjointHousesAndFunctionality,
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var ExampleExprOrCondsExclude = registerExample(&Example{
	Name:               "ExampleExprOrCondsExclude",
	VMs:                vmsHouses,
	VMsTags:            vmsHousesTags,
	GroupsByExpr:       getAndOrOrExpr(Or),
	Policies:           getAndOrOrPolicies(Or, true),
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
	slyCondDB, hufCondDB, gryCondDB := getOrOrAndGroupNames(op)
	slyAndOrDBExpr := ExampleExpr{Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}, Op: op,
		Cond2: &ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}}
	hufAndOrDBExpr := ExampleExpr{Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}, Op: op,
		Cond2: &ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}}
	gryAndOrDBExpr := ExampleExpr{Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}, Op: op,
		Cond2: &ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}}
	return map[string]ExampleExpr{
		sly:       {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}},
		gry:       {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}},
		huf:       {Cond1: &ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}},
		slyCondDB: slyAndOrDBExpr,
		hufCondDB: hufAndOrDBExpr,
		gryCondDB: gryAndOrDBExpr,
	}
}

func getOrOrAndGroupNames(op ExampleOp) (slyDB, hufDB, gryDB string) {
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

func getAndOrOrPolicies(op ExampleOp, withExclude bool) []Category {
	slyCondDB, hufCondDB, gryCondDB := getOrOrAndGroupNames(op)
	return []Category{
		{
			Name:         "Protect-DBs",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:      "to-Slytherin-in",
					ID:        newRuleID,
					Source:    AnyStr,
					Dest:      AnyStr,
					Scope:     slyCondDB,
					Services:  []string{AnyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "to-Slytherin-out",
					ID:        newRuleID + 1,
					Source:    AnyStr,
					Dest:      slyCondDB,
					Scope:     gry,
					Services:  []string{AnyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "to-Gryffindor-in",
					ID:        newRuleID + 2,
					Source:    AnyStr,
					Dest:      gryCondDB,
					Services:  []string{AnyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name: "to-Hufflepuff-out",
					//nolint:all // this is the required id
					ID:                   newRuleID + 3,
					Source:               AnyStr,
					Dest:                 hufCondDB,
					DestinationsExcluded: withExclude,
					Services:             []string{AnyStr},
					Action:               Allow,
					Direction:            string(nsx.RuleDirectionOUT),
				},
				{
					Name: "default-deny-env",
					//nolint:all // this is the required id
					ID:       10300,
					Source:   AnyStr,
					Dest:     AnyStr,
					Services: []string{AnyStr},
					Action:   Drop,
				},
			},
		},
	}
}

var ExampleHogwartsSimplerNonSymInOut = registerExample(&Example{
	Name: "ExampleHogwartsSimplerNonSymInOut",
	VMs: []string{SlyWeb, slyApp, slyDB,
		GryWeb, gryApp, gryDB},
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
					Dest:      AnyStr,
					Scope:     gry,
					Action:    JumpToApp,
					Conn:      netset.AllTransports(),
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow-Gryffindor-to-Gryffindor-out",
					ID:        10219,
					Source:    AnyStr,
					Dest:      gry,
					Scope:     gry,
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
					Dest:      AnyStr,
					Scope:     sly,
					Action:    JumpToApp,
					Conn:      netset.AllUDPTransport().Union(netset.AllTCPTransport()),
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "allow-Slytherin-to-Slytherin-out",
					ID:        10221,
					Source:    AnyStr,
					Scope:     sly,
					Dest:      sly,
					Action:    JumpToApp,
					Conn:      netset.AllUDPTransport(),
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:     "default-deny-env",
					ID:       10231,
					Source:   AnyStr,
					Dest:     AnyStr,
					Services: []string{AnyStr},
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
					Source:    AnyStr,
					Dest:      web,
					Action:    Allow,
					Conn:      netset.AllTransports(),
					Direction: string(nsx.RuleDirectionIN),
				},
				{
					Name:      "Client-Access-out",
					ID:        11001,
					Source:    AnyStr,
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

var ExampleHogwartsExcludeSimple = registerExample(&Example{
	Name: "ExampleHogwartsExcludeSimple",
	VMs: []string{SlyWeb, slyApp, slyDB,
		GryWeb, gryApp, gryDB,
		HufWeb, hufApp, hufDB},
	GroupsByVMs: hogwartsBidimensionalGroups,
	Policies: []Category{
		{
			Name:         "allow-inbound",
			CategoryType: environment,
			Rules: []Rule{
				{
					Name:      "allow-all-in",
					ID:        10218,
					Source:    AnyStr,
					Dest:      AnyStr,
					Action:    Allow,
					Conn:      netset.AllTransports(),
					Direction: string(nsx.RuleDirectionIN),
				},
			},
		},
		{
			Name:         "allow-out",
			CategoryType: application,
			Rules: []Rule{
				{
					Name:                 "allow-Slytherin-to-nonSlytherin-out",
					ID:                   10220,
					Source:               sly,
					Dest:                 sly,
					DestinationsExcluded: true,
					Action:               Allow,
					Conn:                 netset.AllUDPTransport().Union(netset.AllTCPTransport()),
					Direction:            string(nsx.RuleDirectionOUT),
				},
				{
					Name:                 "allow-Gryffindor-to-nonGryffindor-out",
					ID:                   10221,
					Source:               gry,
					Dest:                 gry,
					DestinationsExcluded: true,
					Action:               Allow,
					Conn:                 netset.AllUDPTransport().Union(netset.AllTCPTransport()),
					Direction:            string(nsx.RuleDirectionOUT),
				},
				{
					Name:                 "allow-Hufflepuff-to-nonHufflepuff-out",
					ID:                   10222,
					Source:               huf,
					Dest:                 huf,
					DestinationsExcluded: true,
					Action:               Allow,
					Conn:                 netset.AllUDPTransport().Union(netset.AllTCPTransport()),
					Direction:            string(nsx.RuleDirectionOUT),
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
	Name: "ExampleHogwartsExternal",
	VMs: []string{SlyWeb, slyApp, slyDB, HufWeb, hufApp, hufDB,
		GryWeb, gryApp, gryDB, Dum1, Dum2},
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
					Source:    AnyStr,
					Dest:      "0.0.0.0/0",
					Scope:     sly,
					Services:  []string{AnyStr},
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
					Dest:      AnyStr,
					Scope:     dum,
					Services:  []string{AnyStr},
					Direction: string(nsx.RuleDirectionIN),
					Action:    JumpToApp,
				},
				{
					Name:     "default-deny-env",
					ID:       10300,
					Source:   AnyStr,
					Dest:     "0.0.0.0/0",
					Services: []string{AnyStr},
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
					Source:    AnyStr,
					Scope:     web,
					Dest:      "0.0.1.0/16",
					Services:  []string{AnyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "App-to-external",
					ID:        10401,
					Source:    AnyStr,
					Dest:      "146.2.0.0/16",
					Scope:     app,
					Services:  []string{AnyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:      "DB-to-external",
					ID:        10405,
					Source:    db,
					Dest:      "220.0.1.0/28",
					Services:  []string{AnyStr},
					Action:    Allow,
					Direction: string(nsx.RuleDirectionOUT),
				},
				{
					Name:   "to-Dumb",
					ID:     10406,
					Source: "122.0.0.0/8",
					// SourcesExcluded: true, // todo: not working!!
					Dest:      dum,
					Services:  []string{AnyStr},
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

var ExampleAppWithGroups = registerExample(&Example{
	Name: "ExampleAppWithGroups",
	VMs:  []string{"New-VM-1", "New-VM-2", "New-VM-3", "New-VM-4", "New Virtual Machine"},
	GroupsByVMs: map[string][]string{
		"research-app":         {"New-VM-1", "New-VM-2", "New-VM-3", "New-VM-4", "New Virtual Machine"},
		"research-seg-1":       {"New-VM-1", "New-VM-3", "New-VM-4"},
		"foo-app":              {"New-VM-3", "New-VM-4"},
		"foo-backend":          {"New-VM-4"},
		"foo-frontend":         {"New-VM-3"},
		"research-test-expr-2": {"New Virtual Machine"},
	},
	Policies: []Category{
		{
			Name:         "foo-app",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:            "allow-icmp-to-backend",
					ID:              1027,
					Source:          "foo-app, research-test-expr-2", // exclude(foo-app,research-test-expr-2)
					SourcesExcluded: true,
					Dest:            "foo-backend",
					Services:        []string{"/infra/services/ICMPv4-ALL"},
					Action:          Allow,
				},
			},
		},
		{
			Name:         "New Policy",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:   "research-seg-1-allow-tcp-udp",
					ID:     1023,
					Source: "research-seg-1",
					Dest:   "research-seg-1",
					Conn:   netset.AllOrNothingTransport(true, false),
					Action: Allow,
				},

				{
					Name:     "research-seg-1-drop-icmp",
					ID:       1022,
					Source:   "research-seg-1",
					Dest:     "research-seg-1",
					Services: []string{"/infra/services/ICMPv4-ALL"},
					Action:   Drop,
				},

				{
					Name:     "allow-research-app-icmp",
					ID:       1009,
					Source:   "research-app",
					Dest:     "research-app",
					Services: []string{"/infra/services/ICMPv4-ALL"},
					Action:   Allow,
				},

				{
					Name:     "allow-research-app-http",
					ID:       1024,
					Source:   "research-app",
					Dest:     "research-app",
					Services: []string{"/infra/services/HTTP"},
					Action:   Allow,
				},

				{
					Name:     "allow-research-app-http-redundant",
					ID:       1020,
					Source:   "research-app",
					Dest:     "research-app",
					Services: []string{"/infra/services/HTTP"},
					Action:   Allow,
				},
			},
		},

		{
			Name:         "Default Layer3 Section",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "deny-research-app",
					ID:       1021,
					Source:   "research-app",
					Dest:     "research-app",
					Services: []string{AnyStr},
					Action:   Drop,
				},
				DefaultDenyRule(2),
			},
		},
	},
})

///////////////////////////////////////////////////////////////////////////////////////////////////////

var ExampleAppWithGroupsAdditionalDropRule = registerExample(createExampleAppWithGroups2())

//nolint:all
func createExampleAppWithGroups2() *Example {
	res := *ExampleAppWithGroups
	res.Policies = slices.Clone(ExampleAppWithGroups.Policies)

	newRules := []Rule{
		{
			Name:     "drop-icmp-foo-app-scope",
			ID:       1028,
			Source:   "research-app",
			Dest:     "research-app",
			Services: []string{"/infra/services/ICMPv4-ALL"},
			Action:   Drop,
			Scope:    "foo-app",
		},
	}

	// add the above rule as first rule in first category
	res.Policies[0].Rules = slices.Concat(newRules, res.Policies[0].Rules)

	res.Name = "ExampleAppWithGroupsAdditionalDropRule"
	return &res
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

var ExampleAppWithGroupsAndSegments = registerExample(&Example{
	Name: "ExampleAppWithGroupsAndSegments",
	VMs:  []string{"New-VM-1", "New-VM-2", "New-VM-3", "New-VM-4", "New Virtual Machine"},
	VMsAddress: map[string]string{
		"New-VM-1":            "192.168.1.1",
		"New-VM-2":            "192.168.1.3",
		"New-VM-3":            "192.168.0.1",
		"New-VM-4":            "192.168.0.2",
		"New Virtual Machine": "192.168.1.2",
	},
	SegmentsByVMs: map[string][]string{
		"T1-192-168-0-0": {"New-VM-3", "New-VM-4"},
		"T1-192-168-1-0": {"New-VM-1", "New-VM-2", "New Virtual Machine"},
	},
	SegmentsBlock: map[string]string{
		"T1-192-168-0-0": "192.168.0.0/24",
		"T1-192-168-1-0": "192.168.1.0/24",
	},
	SegmentsT1GWs: map[string]string{
		"T1-192-168-0-0": "T1-workloads",
		"T1-192-168-1-0": "T1-workloads",
	},
	GroupsByVMs: map[string][]string{
		"research-app":         {"New-VM-1", "New-VM-2", "New-VM-3", "New-VM-4", "New Virtual Machine"},
		"research-seg-1":       {"New-VM-1", "New-VM-3", "New-VM-4"},
		"foo-app":              {"New-VM-3", "New-VM-4"},
		"bar-app":              {"New-VM-1", "New-VM-2", "New Virtual Machine"},
		"foo-backend":          {"New-VM-4"},
		"foo-frontend":         {"New-VM-3"},
		"research-test-expr-2": {"New-VM-1"},
	},
	Policies: []Category{
		{
			Name:         "foo-app",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "foo-allow-http-to-backend",
					ID:       1027,
					Source:   "foo-frontend",
					Dest:     "foo-backend",
					Services: []string{"/infra/services/HTTP"},
					Action:   Allow,
				},
				{
					Name:     "default-deny-foo-app",
					ID:       1028,
					Source:   "foo-app",
					Dest:     "foo-app",
					Services: []string{AnyStr},
					Action:   Drop,
				},
			},
		},
		{
			Name:         "New Policy",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "allow-smb-to-foo-frontend",
					ID:       1025,
					Source:   "research-test-expr-2",
					Dest:     "foo-frontend",
					Services: []string{"/infra/services/SMB"},
					Action:   Allow,
				},
				{
					Name:     "allow-bar-app-https",
					ID:       1024,
					Source:   "bar-app",
					Dest:     "bar-app",
					Services: []string{"/infra/services/HTTPS"},
					Action:   Allow,
				},
			},
		},
		{
			Name:         "Default Layer3 Section",
			CategoryType: "Application",
			Rules: []Rule{
				{
					Name:     "deny-research-app",
					ID:       1021,
					Source:   "research-app",
					Dest:     "research-app",
					Services: []string{AnyStr},
					Action:   Drop,
				},
				DefaultDenyRule(2),
			},
		},
	},
})
