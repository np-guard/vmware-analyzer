/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/version"
)

const (
	resourceInputFileFlag = "resource-input-file"
	hostFlag              = "host"
	userFlag              = "username"
	passwordFlag          = "password"
	resourceDumpFileFlag  = "resource-dump-file"
	skipAnalysisFlag      = "skip-analysis"
	outputFileFlag        = "output-file"

	resourceInputFileHelp = "help for resource-input-file"
	hostHelp              = "help for host"
	userHelp              = "help for username"
	passwordHelp          = "help for password"
	resourceDumpFileHelp  = "help for resource-dump-file"
	skipAnalysisHelp      = "help for skip-analysis"
	outputFileHelp        = "help for output-file"
)

type inArgs struct {
	resourceInputFile string
	host              string
	user              string
	password          string
	resourceDumpFile  string
	skipAnalysis      bool
	outputFile        string
}

func newRootCommand() *cobra.Command {
	args := &inArgs{}
	rootCmd := &cobra.Command{
		Use:   "nsxanalyzer",
		Short: `nsxanalyzer is a CLI for collecting NSX resources, and analyzing permitted connectivity between VMs.`,
		Long: `nsxanalyzer is a CLI for collecting NSX resources, and analyzing permitted connectivity between VMs.
		It uses REST API calls from NSX manager. `,
		Version: version.VersionCore,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCommand(args)
		},
	}

	rootCmd.PersistentFlags().StringVar(&args.resourceInputFile, resourceInputFileFlag, "", resourceInputFileHelp)
	rootCmd.PersistentFlags().StringVar(&args.host, hostFlag, "", hostHelp)
	rootCmd.PersistentFlags().StringVar(&args.user, userFlag, "", userHelp)
	rootCmd.PersistentFlags().StringVar(&args.password, passwordFlag, "", passwordHelp)
	rootCmd.PersistentFlags().StringVar(&args.resourceDumpFile, resourceDumpFileFlag, "", resourceDumpFileHelp)
	rootCmd.PersistentFlags().BoolVar(&args.skipAnalysis, skipAnalysisFlag, false, skipAnalysisHelp)
	rootCmd.PersistentFlags().StringVar(&args.outputFile, outputFileFlag, "", outputFileHelp)

	rootCmd.MarkFlagsOneRequired(resourceInputFileFlag, hostFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, hostFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, userFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, passwordFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, resourceDumpFileFlag)
	rootCmd.MarkFlagsMutuallyExclusive(skipAnalysisFlag, outputFileFlag)
	rootCmd.MarkFlagsRequiredTogether(userFlag, passwordFlag)

	return rootCmd
}

func runCommand(args *inArgs) error {
	var recourses *collector.ResourcesContainerModel
	var err error
	if args.host != "" {
		fmt.Println("collecting NSX resources from given host")
		recourses, err = collector.CollectResources(args.host, args.user, args.password)
		if err != nil {
			return err
		}
	} else {
		b, err := os.ReadFile(args.resourceInputFile)
		if err != nil {
			return err
		}
		fmt.Println("reading input NSX config file")
		recourses, err = collector.FromJSONString(b)
		if err != nil {
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
	if !args.skipAnalysis {
		connResStr, err := model.NSXConnectivityFromResourcesContainer(recourses)
		if err != nil {
			return err
		}
		fmt.Println("analyzed Connectivity:")
		fmt.Println(connResStr)

		if args.outputFile != "" {
			err = common.WriteToFile(args.outputFile, "analyze output")
			if err != nil {
				return err
			}
		}
	}
	return nil
}
