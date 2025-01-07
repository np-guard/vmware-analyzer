/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/np-guard/vmware-analyzer/pkg/anonymizer"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/version"
)

const (
	resourceInputFileFlag  = "resource-input-file"
	hostFlag               = "host"
	userFlag               = "username"
	passwordFlag           = "password"
	resourceDumpFileFlag   = "resource-dump-file"
	topologyDumpFileFlag   = "topology-dump-file"
	skipAnalysisFlag       = "skip-analysis"
	anonymizeFlag          = "anonymize"
	outputFileFlag         = "filename"
	outputFormantFlag      = "output"
	outputFileShortFlag    = "f"
	outputFormantShortFlag = "o"
	outputFilterFlag       = "output-filter"
	quietFlag              = "quiet"
	verboseFlag            = "verbose"
	explainFlag            = "explain"

	resourceInputFileHelp = "file path input JSON of NSX resources"
	hostHelp              = "nsx host url"
	userHelp              = "nsx username"
	passwordHelp          = "nsx password"
	resourceDumpFileHelp  = "file path to store collected resources in JSON format"
	topologyDumpFileHelp  = "file path to store topology"
	skipAnalysisHelp      = "flag to skip analysis, run only collector"
	anonymizeHelp         = "flag to anonymize resources"
	outputFileHelp        = "file path to store analysis results"
	outputFormatHelp      = "output format; must be one of [txt, dot, json, svg]"
	outputFilterFlagHelp  = "filter the analysis results, can have more than one"
)

type inArgs struct {
	resourceInputFile string
	host              string
	user              string
	password          string
	resourceDumpFile  string
	topologyDumpFile  string
	skipAnalysis      bool
	anonymise         bool
	outputFile        string
	outputFormat      string
	quiet             bool
	verbose           bool
	explain           bool
	outputFilter      []string
}

func newRootCommand() *cobra.Command {
	args := &inArgs{}
	rootCmd := &cobra.Command{
		Use:   "nsxanalyzer",
		Short: `nsxanalyzer is a CLI for collecting NSX resources, and analyzing permitted connectivity between VMs.`,
		Long: `nsxanalyzer is a CLI for collecting NSX resources, and analyzing permitted connectivity between VMs.
It uses REST API calls from NSX manager. `,
		Version: version.VersionCore,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			verbosity := logging.MediumVerbosity
			if args.quiet {
				verbosity = logging.LowVerbosity
			} else if args.verbose {
				verbosity = logging.HighVerbosity
			}
			logging.Init(verbosity) // initializes a thread-safe singleton logger
		},

		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args)
		},
	}

	rootCmd.PersistentFlags().StringVarP(&args.resourceInputFile, resourceInputFileFlag, "r", "", resourceInputFileHelp)
	rootCmd.PersistentFlags().StringVar(&args.host, hostFlag, "", hostHelp)
	rootCmd.PersistentFlags().StringVar(&args.user, userFlag, "", userHelp)
	rootCmd.PersistentFlags().StringVar(&args.password, passwordFlag, "", passwordHelp)
	rootCmd.PersistentFlags().StringVar(&args.resourceDumpFile, resourceDumpFileFlag, "", resourceDumpFileHelp)
	rootCmd.PersistentFlags().StringVar(&args.topologyDumpFile, topologyDumpFileFlag, "", topologyDumpFileHelp)
	rootCmd.PersistentFlags().BoolVar(&args.skipAnalysis, skipAnalysisFlag, false, skipAnalysisHelp)
	rootCmd.PersistentFlags().BoolVar(&args.anonymise, anonymizeFlag, false, anonymizeHelp)
	rootCmd.PersistentFlags().StringVarP(&args.outputFile, outputFileFlag, outputFileShortFlag, "", outputFileHelp)
	// todo - check if the format is valid
	rootCmd.PersistentFlags().StringVarP(&args.outputFormat, outputFormantFlag, outputFormantShortFlag, common.TextFormat, outputFormatHelp)
	rootCmd.PersistentFlags().BoolVarP(&args.quiet, quietFlag, "q", false, "runs quietly, reports only severe errors and results")
	rootCmd.PersistentFlags().BoolVarP(&args.verbose, verboseFlag, "v", false, "runs with more informative messages printed to log")
	rootCmd.PersistentFlags().BoolVarP(&args.explain, explainFlag, "e", false, "connectivity output with rules explanations per allowed/denied connections")
	rootCmd.PersistentFlags().StringSliceVar(&args.outputFilter, outputFilterFlag, nil, outputFilterFlagHelp)

	rootCmd.MarkFlagsOneRequired(resourceInputFileFlag, hostFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, hostFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, userFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, passwordFlag)
	rootCmd.MarkFlagsMutuallyExclusive(skipAnalysisFlag, outputFileFlag)
	rootCmd.MarkFlagsRequiredTogether(userFlag, passwordFlag)
	rootCmd.MarkFlagsMutuallyExclusive(skipAnalysisFlag, outputFormantFlag)

	return rootCmd
}

func runCommand(args *inArgs) error {
	var recourses *collector.ResourcesContainerModel
	var err error
	if args.host != "" {
		logging.Infof("collecting NSX resources from given host %s", args.host)
		server := collector.NewServerData(args.host, args.user, args.password)
		recourses, err = collector.CollectResources(server)
		if err != nil {
			return err
		}
	} else {
		logging.Infof("reading input NSX config file %s", args.resourceInputFile)
		b, err := os.ReadFile(args.resourceInputFile)
		if err != nil {
			return err
		}
		recourses, err = collector.FromJSONString(b)
		if err != nil {
			return err
		}
	}
	if args.anonymise {
		if err := anonymizer.AnonymizeNsx(recourses); err != nil {
			return err
		}
	}
	if args.resourceDumpFile != "" {
		jsonString, err := recourses.ToJSONString()
		if err != nil {
			return err
		}
		err = common.WriteToFile(args.resourceDumpFile, jsonString)
		if err != nil {
			return err
		}
	}
	if args.topologyDumpFile != "" {
		topology, err := recourses.OutputTopologyGraph(args.topologyDumpFile, args.outputFormat)
		if err != nil {
			return err
		}
		fmt.Println(topology)
	}
	if !args.skipAnalysis {
		params := common.OutputParameters{
			Format:   args.outputFormat,
			FileName: args.outputFile,
			VMs:      args.outputFilter,
			Explain:  args.explain,
		}
		logging.Infof("starting connectivity analysis")
		connResStr, err := model.NSXConnectivityFromResourcesContainer(recourses, params)
		if err != nil {
			return err
		}
		fmt.Println(connResStr)
	}
	return nil
}
