package cli

import "github.com/spf13/cobra"

func newCommandLint() *cobra.Command {
	c := &cobra.Command{
		Use:   "lint",
		Short: "Lint input NSX config - show potential DFW redundant rules",
		Example: `  # Lint NSX DFW 
	nsxanalyzer lint -r config.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args, cmdLint)
			// return nil
		},
	}
	return c
}
