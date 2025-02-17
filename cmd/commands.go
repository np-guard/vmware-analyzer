/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/spf13/cobra"

	"github.com/np-guard/vmware-analyzer/pkg/runner"
	"github.com/np-guard/vmware-analyzer/pkg/version"
)

const (
	resourceInputFileFlag       = "resource-input-file"
	hostFlag                    = "host"
	userFlag                    = "username"
	passwordFlag                = "password"
	resourceDumpFileFlag        = "resource-dump-file"
	topologyDumpFileFlag        = "topology-dump-file"
	skipAnalysisFlag            = "skip-analysis"
	anonymizeFlag               = "anonymize"
	synthesisDumpDirFlag        = "synthesis-dump-dir"
	synthesizeAdminPoliciesFlag = "synthesize-admin-policies"
	logFileFlag                 = "log-file"
	outputFileFlag              = "filename"
	outputFormatFlag            = "output"
	outputFileShortFlag         = "f"
	outputFormantShortFlag      = "o"
	outputFilterFlag            = "output-filter"
	quietFlag                   = "quiet"
	verboseFlag                 = "verbose"
	explainFlag                 = "explain"
	colorFlag                   = "color"
	createDNSPolicyFlag         = "synth-create-dns-policy"
	disjointHintsFlag           = "disjoint-hint"

	resourceInputFileHelp       = "file path input JSON of NSX resources (instead of collecting from NSX host)"
	hostHelp                    = "NSX host URL. Alternatively, set the host via the NSX_HOST environment variable"
	userHelp                    = "NSX username. Alternatively, set the username via the NSX_USER environment variable"
	passwordHelp                = "NSX password. Alternatively, set the password via the NSX_PASSWORD environment variable" // #nosec G101
	resourceDumpFileHelp        = "file path to store collected resources in JSON format"
	topologyDumpFileHelp        = "file path to store topology"
	skipAnalysisHelp            = "flag to skip analysis, run only collector and/or synthesis (default false)"
	anonymizeHelp               = "flag to anonymize collected NSX resources (default false)"
	logFileHelp                 = "file path to write nsxanalyzer log"
	outputFileHelp              = "file path to store analysis results"
	explainHelp                 = "flag to explain connectivity output with rules explanations per allowed/denied connections (default false)"
	synthesisDumpDirHelp        = "apply synthesis; specify directory path to store k8s synthesis results"
	synthesizeAdminPoliciesHelp = "include admin network policies in policy synthesis (default false)"
	outputFormatHelp            = "output format; must be one of "
	outputFilterFlagHelp        = "filter the analysis results by vm names, can specify more than one (example: \"vm1,vm2\")"
	quietHelp                   = "flag to run quietly, report only severe errors and result (default false)"
	verboseHelp                 = "flag to run with more informative messages printed to log (default false)"
	colorHelp                   = "flag to enable color output (default false)"
	createDNSPolicyHelp         = "flag to create a policy allowing access to target env dns pod"
	disjointHintsHelp           = "comma separated list of NSX groups/tags that are always disjoint in their VM members," +
		" needed for an effective and sound synthesis process, can specify more than one hint" +
		" (example: \"--" + disjointHintsFlag + " frontend,backend --" + disjointHintsFlag + " app,web,db\")"
)

type inArgs struct {
	resourceInputFile string
	host              string
	user              string
	password          string
	resourceDumpFile  string
	topologyDumpFile  string
	synthesisDumpDir  string
	synthesizeAdmin   bool
	skipAnalysis      bool
	anonymise         bool
	logFile           string
	outputFile        string
	outputFormat      outFormat
	quiet             bool
	verbose           bool
	explain           bool
	outputFilter      []string
	color             bool
	createDNSPolicy   bool
	disjointHints     []string
}

func newInArgs() *inArgs {
	return &inArgs{outputFormat: outFormatText} // init with default val for outputFormat
}

func newRootCommand() *cobra.Command {
	args := newInArgs()
	rootCmd := &cobra.Command{
		Use: "nsxanalyzer",
		Short: `nsxanalyzer is a CLI for collecting NSX resources, analysis of permitted connectivity between VMs,
and generation of k8s network policies`,
		Long: `nsxanalyzer is a CLI for collecting NSX resources, analysis of permitted connectivity between VMs,
and generation of k8s network policies. It uses REST API calls from NSX manager. `,
		Version: version.VersionCore,
		/*PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			verbosity := logging.MediumVerbosity
			if args.quiet {
				verbosity = logging.LowVerbosity
			} else if args.verbose {
				verbosity = logging.HighVerbosity
			}
			return logging.Init(verbosity, args.logFile) // initializes a thread-safe singleton logger
		},*/

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
	rootCmd.PersistentFlags().StringVar(&args.synthesisDumpDir, synthesisDumpDirFlag, "", synthesisDumpDirHelp)
	rootCmd.PersistentFlags().BoolVar(&args.synthesizeAdmin, synthesizeAdminPoliciesFlag, false, synthesizeAdminPoliciesHelp)
	rootCmd.PersistentFlags().StringVarP(&args.outputFile, outputFileFlag, outputFileShortFlag, "", outputFileHelp)
	rootCmd.PersistentFlags().VarP(&args.outputFormat, outputFormatFlag, outputFormantShortFlag, outputFormatHelp+allFormatsStr)
	rootCmd.PersistentFlags().BoolVarP(&args.quiet, quietFlag, "q", false, quietHelp)
	rootCmd.PersistentFlags().BoolVarP(&args.verbose, verboseFlag, "v", false, verboseHelp)
	rootCmd.PersistentFlags().BoolVarP(&args.explain, explainFlag, "e", false, explainHelp)
	rootCmd.PersistentFlags().BoolVar(&args.color, colorFlag, false, colorHelp)
	rootCmd.PersistentFlags().StringSliceVar(&args.outputFilter, outputFilterFlag, nil, outputFilterFlagHelp)
	rootCmd.PersistentFlags().BoolVar(&args.createDNSPolicy, createDNSPolicyFlag, true, createDNSPolicyHelp)
	rootCmd.PersistentFlags().StringArrayVar(&args.disjointHints, disjointHintsFlag, nil, disjointHintsHelp)
	rootCmd.PersistentFlags().StringVar(&args.logFile, logFileFlag, "", logFileHelp)

	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, hostFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, userFlag)
	rootCmd.MarkFlagsMutuallyExclusive(resourceInputFileFlag, passwordFlag)
	rootCmd.MarkFlagsMutuallyExclusive(skipAnalysisFlag, outputFileFlag)
	rootCmd.MarkFlagsMutuallyExclusive(skipAnalysisFlag, outputFormatFlag)

	return rootCmd
}

// NewPRunnerWithOptionsList
func runCommand(args *inArgs) error {
	runnerObj, err := runner.NewPRunnerWithOptionsList(
		runner.WithOutputFormat(args.outputFormat.String()),
		runner.WithOutputColor(args.color),
		runner.WithHighVerbosity(args.verbose),
		runner.WithQuietVerbosity(args.quiet),
		runner.WithLogFile(args.logFile),
		runner.WithNSXURL(args.host),
		runner.WithNSXUser(args.user),
		runner.WithNSXPassword(args.password),
		runner.WithResourcesDumpFile(args.resourceDumpFile),
		runner.WithResourcesAnonymization(args.anonymise),
		runner.WithResourcesInputFile(args.resourceInputFile),
		runner.WithTopologyDumpFile(args.topologyDumpFile),
		runner.WithSkipAnalysis(args.skipAnalysis),
		runner.WithAnalysisOutputFile(args.outputFile),
		runner.WithAnalysisExplain(args.explain),
		runner.WithAnalysisVMsFilter(args.outputFilter),
		runner.WithSynthesisDumpDir(args.synthesisDumpDir),
		runner.WithSynthAdminPolicies(args.synthesizeAdmin),
		runner.WithSynthesisHints(args.disjointHints),
	)
	if err != nil {
		return err
	}
	return runnerObj.Run()
}

/*
//nolint:gocyclo // one function with lots of options
func runCommand(args *inArgs) error {
	var resources *collector.ResourcesContainerModel
	var err error
	if args.resourceInputFile != "" {
		resources, err = resourcesFromInputFile(args.resourceInputFile)
	} else {
		resources, err = resourcesFromNSXEnv(args)
	}
	if err != nil {
		return err
	}

	if args.anonymise {
		if err := anonymizer.AnonymizeNsx(resources); err != nil {
			return err
		}
	}
	if args.resourceDumpFile != "" {
		jsonString, err := resources.ToJSONString()
		if err != nil {
			return err
		}
		err = common.WriteToFile(args.resourceDumpFile, jsonString)
		if err != nil {
			return err
		}
	}
	if args.topologyDumpFile != "" {
		topology, err := resources.OutputTopologyGraph(args.topologyDumpFile, args.outputFormat.String())
		if err != nil {
			return err
		}
		fmt.Println(topology)
	}
	if !args.skipAnalysis {
		params := common.OutputParameters{
			Format:   args.outputFormat.String(),
			FileName: args.outputFile,
			VMs:      args.outputFilter,
			Explain:  args.explain,
			Color:    args.color,
		}
		logging.Infof("starting connectivity analysis")
		connResStr, err := model.NSXConnectivityFromResourcesContainer(resources, params)
		if err != nil {
			return err
		}
		fmt.Println(connResStr)
	}
	if args.synthesisDumpDir != "" {
		hints := &symbolicexpr.Hints{GroupsDisjoint: make([][]string, len(args.disjointHints))}
		for i, hint := range args.disjointHints {
			hints.GroupsDisjoint[i] = strings.Split(hint, common.CommaSeparator)
		}
		options := &synthesis.SynthesisOptions{
			Hints:           hints,
			SynthesizeAdmin: args.synthesizeAdmin,
			CreateDNSPolicy: args.createDNSPolicy,
			Color:           args.color,
		}
		resources, err := synthesis.NSXToK8sSynthesis(resources, options)
		if err != nil {
			return err
		}
		err = resources.CreateDir(args.synthesisDumpDir)
		if err != nil {
			return err
		}
	}
	return nil
}
*/
