package data

import (
	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

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

var ExampleHogwarts = Example{
	Name: "ExampleHogwarts",
	VMs: []string{slyWeb, slyApp, slyDB, hufWeb, hufApp, hufDB,
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
}
