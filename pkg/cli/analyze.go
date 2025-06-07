package cli

import (
	"github.com/spf13/cobra"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

func newCommandAnalyze() *cobra.Command {
	c := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze NSX connectivity from NSX DFW configuration",
		Example: `  # Analyze NSX configuration 
	nsxanalyzer analyze -r config.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args, common.CmdAnalyze)
		},
	}

	c.PersistentFlags().StringVarP(&args.OutputFile, outputFileFlag, outputFileShortFlag, "", outputFileHelp)
	c.PersistentFlags().VarP(&args.OutputFormat, outputFormatFlag, outputFormantShortFlag, outputFormatHelp+common.AllFormatsStr)
	c.PersistentFlags().StringSliceVar(&args.OutputFilter, outputFilterFlag, nil, outputFilterFlagHelp)
	c.PersistentFlags().BoolVarP(&args.Explain, explainFlag, "e", false, explainHelp)
	c.PersistentFlags().StringVar(&args.TopologyDumpFile, topologyDumpFileFlag, "", topologyDumpFileHelp)
	return c
}
