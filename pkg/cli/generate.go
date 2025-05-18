package cli

import (
	"github.com/spf13/cobra"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

func newCommandGenerate() *cobra.Command {
	c := &cobra.Command{
		Use:     "generate",
		Short:   "Generate OCP-Virt micro-segmentation resources from input NSX config",
		Aliases: []string{"synthesize"},
		Example: `  # Generate OCP-Virt netpol resources
	nsxanalyzer generate -r config.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args, cmdGenerate)
		},
	}

	c.PersistentFlags().StringVarP(&args.synthesisDir, synthesisDirFlag, "d", "", synthesisDirHelp)
	c.PersistentFlags().BoolVar(&args.synthesizeAdmin, synthesizeAdminPoliciesFlag, false, synthesizeAdminPoliciesHelp)
	c.PersistentFlags().BoolVar(&args.createDNSPolicy, createDNSPolicyFlag, true, createDNSPolicyHelp)
	c.PersistentFlags().BoolVar(&args.inferDisjointHints, inferDisjointHintsFlag, false, inferDisjointHintsFlagHelp)
	c.PersistentFlags().StringArrayVar(&args.disjointHints, disjointHintsFlag, nil, disjointHintsHelp)
	c.PersistentFlags().StringSliceVar(&args.outputFilter, outputFilterFlag, nil, outputFilterFlagHelp)
	c.PersistentFlags().Var(&args.endpointsMapping, endpointsMappingFlag, endpointsMappingHelp+common.AllEndpointsStr)
	c.PersistentFlags().Var(&args.segmentsMapping, segmentsMappingFlag, segmentsMappingHelp+common.AllSegmentOptionsStr)
	return c
}
