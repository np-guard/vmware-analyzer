package cli

import "github.com/spf13/cobra"

func newCommandCollect() *cobra.Command {
	c := &cobra.Command{
		Use:     "collect",
		Short:   "Collect NSX configuration from given NSX URL",
		Aliases: []string{"export"},
		Example: `  # Collect NSX configuration and store as JSON file
	nsxanalyzer collect -f config.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args, cmdCollect)
		},
	}

	// add flags
	c.PersistentFlags().BoolVar(&args.anonymize, anonymizeFlag, false, anonymizeHelp)
	return c
}
