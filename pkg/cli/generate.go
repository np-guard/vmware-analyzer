package cli

import "github.com/spf13/cobra"

func newCommandGenerate() *cobra.Command {
	c := &cobra.Command{
		Use:     "generate",
		Short:   "Generate OCP-Virt micro-segmentation resources from input NSX config",
		Aliases: []string{"synthesize"},
		Example: `  # Generate OCP-Virt netpol resources
	nsxanalyzer generate -r config.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args, cmdGenerate)
			// return nil
		},
	}

	c.PersistentFlags().StringVar(&args.synthesisDumpDir, synthesisDumpDirFlag, "", synthesisDumpDirHelp)
	c.PersistentFlags().BoolVar(&args.synthesizeAdmin, synthesizeAdminPoliciesFlag, false, synthesizeAdminPoliciesHelp)
	c.PersistentFlags().BoolVar(&args.createDNSPolicy, createDNSPolicyFlag, true, createDNSPolicyHelp)
	c.PersistentFlags().StringArrayVar(&args.disjointHints, disjointHintsFlag, nil, disjointHintsHelp)
	return c
}
