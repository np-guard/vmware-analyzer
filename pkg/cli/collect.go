package cli

import (
	"github.com/spf13/cobra"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

func newCommandCollect() *cobra.Command {
	c := &cobra.Command{
		Use:     "collect",
		Short:   "Collect NSX configuration from given NSX URL",
		Aliases: []string{"export"},
		Example: `  # Collect NSX configuration and store as JSON file
	nsxanalyzer collect -f config.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args, common.CmdCollect)
		},
	}

	// add flags
	c.PersistentFlags().BoolVar(&args.Anonymize, anonymizeFlag, false, anonymizeHelp)
	return c
}
