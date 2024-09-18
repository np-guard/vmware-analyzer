/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/spf13/cobra"

	"github.com/np-guard/vmware-analyzer/pkg/version"
)

const (
	resourceInputFileFlag = "resource-input-file"
	hostFlag              = "host"
	userFlag              = "username"
	passwordFlag          = "password"
	resourceDumpFileFlag  = "resource-dump-file"
	skipAnalysisFlag      = "skip-analysis"
	dumpConfigFileFlag    = "dump-config-file"

	resourceInputFileHelp = "help for resource-input-file"
	hostHelp              = "help for host"
	userHelp              = "help for username"
	passwordHelp          = "help for password"
	resourceDumpFileHelp  = "help for resource-dump-file"
	skipAnalysisHelp      = "help for skip-analysis"
	dumpConfigFileHelp    = "help for dump-config-file"
)

type inArgs struct {
	resourceInputFile string
	host              string
	user              string
	password          string
	resourceDumpFile  string
	skipAnalysis      bool
	dumpConfigFile    string
}

func newRootCommand() *cobra.Command {
	args := &inArgs{}
	rootCmd := &cobra.Command{
		Use:     "vmware-analyzer",
		Short:   "vmware-analyzer is a CLI for collecting and analyzing vmware-related cloud resources",
		Long:    `vmware-analyzer ...`,
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
	rootCmd.PersistentFlags().StringVar(&args.dumpConfigFile, dumpConfigFileFlag, "", dumpConfigFileHelp)

	return rootCmd
}

func runCommand(args *inArgs) error {
	return nil
}
