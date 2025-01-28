package tests

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	denyRuleIDEnv = 2144
	newRuleID     = 1925
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

type ExampleSynthesis struct {
	FromNSX        data.Example
	DisjointGroups [][]string
}

var Example1c = ExampleSynthesis{
	FromNSX: data.Example1c,
}

// ExampleDumbeldore
// Dumbledore1 can communicate to all
// Dumbledore2 can communicate to all but slytherin
var ExampleDumbeldore = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{sly, huf, gry, dum1, dum2},
		GroupsByVMs: map[string][]string{
			sly:               {sly},
			huf:               {huf},
			gry:               {gry},
			dum:               {dum1, dum2},
			"DumbledoreAll":   {dum1},
			"DumbledoreNoSly": {dum2},
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
						Dest:     sly,
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
	FromNSX: data.Example{VMs: []string{sly, huf, gry, dum1, dum2},
		GroupsByVMs: map[string][]string{
			sly:  {sly},
			huf:  {huf},
			gry:  {gry},
			dum:  {dum1, dum2},
			dum1: {dum1},
			dum2: {dum2},
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
						Dest:     dum1,
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "no-conn-to-dumb2",
						ID:       2,
						Source:   "ANY",
						Dest:     dum2,
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Slytherin-to-all",
						ID:       3,
						Source:   sly,
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Gryffindor-to-all",
						ID:       4,
						Source:   gry,
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
		{sly, huf, gry, dum1, dum2},
	},
}

// ExampleDenyPassSimple one pass and two denies, span over two categories
// all can talk to all but Slytherin and Hufflepuff (or to Gryffindor and Dumbledore)
var ExampleDenyPassSimple = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{sly, huf, gry, dum1, dum2},
		GroupsByVMs: map[string][]string{
			sly:  {sly},
			huf:  {huf},
			gry:  {gry},
			dum:  {dum1, dum2},
			dum1: {dum1},
			dum2: {dum2},
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
						Dest:     dum,
						Services: []string{"ANY"},
						Action:   data.JumpToApp,
					},
					{
						Name:     "deny-all-to-Hufflepuff",
						ID:       10219,
						Source:   "ANY",
						Dest:     huf,
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "deny-all-to-Slytherin",
						ID:       10220,
						Source:   "ANY",
						Dest:     sly,
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
		{sly, huf, gry, dum, dum1, dum2},
	},
}

// ExampleHintsDisjoint for testing the hint of disjoint groups/tags and relevant optimization
// Dumbledore1 can talk to all but Slytherin
// Dumbledore2 can talk to all but Gryffindor
var ExampleHintsDisjoint = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{sly, huf, gry, dum1, dum2},
		GroupsByVMs: map[string][]string{
			sly:  {sly},
			huf:  {huf},
			gry:  {gry},
			dum1: {dum1},
			dum2: {dum2},
		},
		Policies: []data.Category{
			{
				Name:         "From-Dumbledore-connection",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Dumb1-Not-Sly",
						ID:       newRuleID,
						Source:   dum1,
						Dest:     sly,
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb2-Not-Gryf",
						ID:       9195,
						Source:   dum2,
						Dest:     gry,
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Dumb1-To-All",
						ID:       9196,
						Source:   dum1,
						Dest:     "ANY",
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Dumb2-To-All",
						ID:       9196,
						Source:   dum2,
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
		{sly, huf, gry, dum1, dum2},
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
	FromNSX: data.Example{VMs: []string{slyWeb, slyApp, slyDB, hufWeb, hufApp, hufDB,
		gryWeb, gryApp, gryDB, dum1, dum2},
		GroupsByVMs: map[string][]string{
			sly: {slyWeb, slyApp, slyDB},
			huf: {hufWeb, hufApp, hufDB},
			gry: {gryWeb, gryApp, gryDB},
			dum: {dum1, dum2},
			web: {slyWeb, gryWeb, hufWeb},
			app: {slyApp, gryApp, hufApp},
			db:  {slyDB, gryDB, hufDB},
		},
		Policies: []data.Category{
			{
				Name:         "Gryffindor-to-Gryffindor-allow",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "allow-Gryffindor-to-Gryffindor",
						ID:       10218,
						Source:   gry,
						Dest:     gry,
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
						Source:   huf,
						Dest:     huf,
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
						Source:   sly,
						Dest:     sly,
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
						Source:   dum,
						Dest:     gry,
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
						Dest:     web,
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Web-To-App-Access",
						ID:       9196,
						Source:   web,
						Dest:     app,
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "App-To-DB-Access",
						ID:       9197,
						Source:   app,
						Dest:     db,
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
		{sly, huf, gry, dum},
		{web, app, db},
		{web, dum},
		{app, dum},
		{db, dum},
	},
}

var ExampleHogwartsSimpler = ExampleSynthesis{
	FromNSX: data.Example{VMs: []string{slyWeb, slyApp, slyDB,
		gryWeb, gryApp, gryDB},
		GroupsByVMs: map[string][]string{
			sly: {slyWeb, slyApp},
			gry: {gryWeb, gryApp},
			web: {slyWeb, gryWeb},
			app: {slyApp, gryApp},
		},
		Policies: []data.Category{
			{
				Name:         "Gryffindor-to-Gryffindor-allow",
				CategoryType: "Environment",
				Rules: []data.Rule{
					{
						Name:     "allow-Gryffindor-to-Gryffindor",
						ID:       10218,
						Source:   gry,
						Dest:     gry,
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
						Source:   sly,
						Dest:     sly,
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
						Dest:     web,
						Services: []string{"ANY"},
						Action:   data.Allow,
					},
					{
						Name:     "Web-To-App-Access",
						ID:       9196,
						Source:   web,
						Dest:     app,
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
		{sly, huf, gry, dum},
		{web, app, db},
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
				Source:   gry,
				Dest:     gry,
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
				Source:   huf,
				Dest:     huf,
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
				Source:   sly,
				Dest:     sly,
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
				Dest:     web,
				Services: []string{"ANY"},
				Action:   data.Allow,
			},
			{
				Name:     "Web-To-App-Access",
				ID:       9196,
				Source:   web,
				Dest:     app,
				Services: []string{"ANY"},
				Action:   data.Allow,
			},
			{
				Name:     "App-To-DB-Access",
				ID:       9197,
				Source:   app,
				Dest:     db,
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
	FromNSX: data.Example{VMs: []string{slyWeb, slyApp, slyDB, hufWeb, hufApp, hufDB,
		gryWeb, gryApp, gryDB},
		GroupsByVMs: map[string][]string{
			sly: {slyWeb, slyApp, slyDB},
			huf: {hufWeb, hufApp, hufDB},
			gry: {gryWeb, gryApp, gryDB},
			web: {slyWeb, gryWeb, hufWeb},
			app: {slyApp, gryApp, hufApp},
			db:  {slyDB, gryDB, hufDB},
		},
		Policies: hogwartsAppToHousesPolicy,
	},
	DisjointGroups: [][]string{
		{sly, huf, gry, dum},
		{web, app, db},
	},
}

// examples with expr instead of direct vms references

var ExampleExprSingleScope = ExampleSynthesis{
	FromNSX: data.Example{
		Name: "ExampleExprSimple",
		VMs:  []string{sly, huf, gry, dum},
		VMsTags: map[string][]nsx.Tag{sly: {{Tag: sly}}, huf: {{Tag: huf}},
			gry: {{Tag: gry}}, dum: {{Tag: dum}}},
		GroupsByExpr: map[string]data.ExampleExpr{
			sly: {Cond1: data.ExampleCond{Tag: nsx.Tag{Tag: sly}}, Op: data.Nop},
			gry: {Cond1: data.ExampleCond{Tag: nsx.Tag{Tag: gry}}, Op: data.Nop},
			huf: {Cond1: data.ExampleCond{Tag: nsx.Tag{Tag: huf}}, Op: data.Nop},
			dum: {Cond1: data.ExampleCond{Tag: nsx.Tag{Tag: dum}}, Op: data.Nop}},
		Policies: []data.Category{
			{
				Name:         "From-Dumbledore-connection",
				CategoryType: "Application",
				Rules: []data.Rule{
					{
						Name:     "Dumb-No-Slytherin",
						ID:       newRuleID,
						Source:   dum,
						Dest:     sly,
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
						Source:   gry,
						Dest:     huf,
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Gryffindor-All",
						ID:       9195,
						Source:   gry,
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
						Source:   huf,
						Dest:     sly,
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Hufflepuff-All",
						ID:       9195,
						Source:   huf,
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
						Source:   sly,
						Dest:     gry,
						Services: []string{"ANY"},
						Action:   data.Drop,
					},
					{
						Name:     "Slytherin-All",
						ID:       9195,
						Source:   sly,
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

var vmsHousesTags = map[string][]nsx.Tag{slyDB: {{Scope: house, Tag: sly}, {Scope: funct, Tag: db}},
	slyWeb: {{Scope: house, Tag: sly}, {Scope: funct, Tag: web}},
	slyApp: {{Scope: house, Tag: sly}, {Scope: funct, Tag: app}},
	hufDB:  {{Scope: house, Tag: huf}, {Scope: funct, Tag: db}},
	hufWeb: {{Scope: house, Tag: huf}, {Scope: funct, Tag: web}},
	hufApp: {{Scope: house, Tag: huf}, {Scope: funct, Tag: app}},
	gryDB:  {{Scope: house, Tag: gry}, {Scope: funct, Tag: db}},
	gryWeb: {{Scope: house, Tag: gry}, {Scope: funct, Tag: web}},
	gryApp: {{Scope: house, Tag: gry}, {Scope: funct, Tag: app}}}

var ExampleExprTwoScopes = ExampleSynthesis{FromNSX: data.Example{
	Name: "ExampleExprSimple",
	VMs: []string{slyDB, slyWeb, slyApp,
		hufDB, hufWeb, hufApp,
		gryDB, gryWeb, gryApp},
	VMsTags: vmsHousesTags,
	GroupsByExpr: map[string]data.ExampleExpr{
		sly: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}, Op: data.Nop},
		gry: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}, Op: data.Nop},
		huf: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}, Op: data.Nop},
		dum: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: dum}}, Op: data.Nop},
		db:  {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}}, Op: data.Nop},
		web: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: web}}, Op: data.Nop},
		app: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: app}}, Op: data.Nop}},
	Policies: hogwartsAppToHousesPolicy,
},
}

var vmsHouses = []string{slyDB, slyWeb, slyApp,
	hufDB, hufWeb, hufApp,
	gryDB, gryWeb, gryApp}

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
		sly: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}, Op: data.Nop},
		gry: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}, Op: data.Nop},
		huf: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}, Op: data.Nop},
		dum: {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: dum}}, Op: data.Nop},
		"Slytherin-orOrAnd-no-DB": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: sly}}, Op: op,
			Cond2: data.ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}},
		"Hufflepuff-orOrAnd-no-DB": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: huf}}, Op: op,
			Cond2: data.ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}},
		"Gryffindor-orOrAnd-no-DB": {Cond1: data.ExampleCond{Tag: nsx.Tag{Scope: house, Tag: gry}}, Op: op,
			Cond2: data.ExampleCond{Tag: nsx.Tag{Scope: funct, Tag: db}, NotEqual: true}}}
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
