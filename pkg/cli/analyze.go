package cli

import "github.com/spf13/cobra"

func newCommandAnalyze() *cobra.Command {
	c := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze NSX connectivity from NSX DFW configuration",
		Example: `  # Analyze NSX configuration 
	nsxanalyzer analyze -r config.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args, cmdAnalyze)
		},
	}

	c.PersistentFlags().StringVarP(&args.outputFile, outputFileFlag, outputFileShortFlag, "", outputFileHelp)
	c.PersistentFlags().VarP(&args.outputFormat, outputFormatFlag, outputFormantShortFlag, outputFormatHelp+allFormatsStr)
	c.PersistentFlags().StringSliceVar(&args.outputFilter, outputFilterFlag, nil, outputFilterFlagHelp)
	c.PersistentFlags().BoolVarP(&args.explain, explainFlag, "e", false, explainHelp)
	c.PersistentFlags().StringVar(&args.topologyDumpFile, topologyDumpFileFlag, "", topologyDumpFileHelp)
	return c
}
