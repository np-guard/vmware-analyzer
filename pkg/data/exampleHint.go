package data

// ExampleHintsDisjoint for testing the hint of disjoint groups/tags and relevant optimization
// Dumbledore1 can talk to all but Slytherin
// Dumbledore2 can talk to all but Gryffindor
var ExampleHintsDisjoint = Example{
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
}
