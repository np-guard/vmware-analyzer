package data

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
				defaultDenyRule(1003),
			},
		},
	},
}
