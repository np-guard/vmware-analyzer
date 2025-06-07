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
			return runCommand(args, common.CmdGenerate)
		},
	}

	c.PersistentFlags().StringVarP(&args.SynthesisDir, synthesisDirFlag, "d", "", synthesisDirHelp)
	c.PersistentFlags().BoolVar(&args.SynthesizeAdmin, synthesizeAdminPoliciesFlag, false, synthesizeAdminPoliciesHelp)
	c.PersistentFlags().BoolVar(&args.CreateDNSPolicy, createDNSPolicyFlag, false, createDNSPolicyHelp)
	c.PersistentFlags().BoolVar(&args.InferDisjointHints, inferDisjointHintsFlag, false, inferDisjointHintsFlagHelp)
	c.PersistentFlags().StringArrayVar(&args.DisjointHints, disjointHintsFlag, nil, disjointHintsHelp)
	c.PersistentFlags().StringSliceVar(&args.OutputFilter, outputFilterFlag, nil, outputFilterFlagHelp)
	c.PersistentFlags().Var(&args.EndpointsMapping, endpointsMappingFlag, endpointsMappingHelp+common.AllEndpointsStr)
	c.PersistentFlags().Var(&args.SegmentsMapping, segmentsMappingFlag, segmentsMappingHelp+common.AllSegmentOptionsStr)
	c.PersistentFlags().Var(&args.PolicyOptimizationLevel, policyOptimizationLevelFlag,
		policyOptimizationLevelHelp+common.AllPolicyOptimizationLevelsStr)

	return c
}
