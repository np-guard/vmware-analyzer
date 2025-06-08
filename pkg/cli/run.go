package cli

import "github.com/np-guard/vmware-analyzer/pkg/runner"

func runCommand(args *inArgs, cmd string) error {
	runnerObj, err := runner.NewRunnerWithOptionsList(
		runner.WithCmd(cmd),
		runner.WithOutputFormat(args.OutputFormat.String()),
		runner.WithOutputColor(args.Color),
		runner.WithHighVerbosity(args.Verbose),
		runner.WithQuietVerbosity(args.Quiet),
		runner.WithLogFile(args.LogFile),
		runner.WithLogLevel(args.LogLevel.String()),
		runner.WithNSXURL(args.Host),
		runner.WithNSXUser(args.User),
		runner.WithNSXPassword(args.Password),
		runner.WithResourcesDumpFile(args.ResourceDumpFile),
		runner.WithResourcesAnonymization(args.Anonymize),
		runner.WithResourcesInputFile(args.ResourceInputFile),
		runner.WithTopologyDumpFile(args.TopologyDumpFile),
		runner.WithAnalysisOutputFile(args.OutputFile),
		runner.WithAnalysisExplain(args.Explain),
		runner.WithAnalysisVMsFilter(args.OutputFilter),
		runner.WithSynthesisDir(args.SynthesisDir),
		runner.WithSynthAdminPolicies(args.SynthesizeAdmin),
		runner.WithSynthesisHints(args.DisjointHints),
		runner.WithSynthDNSPolicies(args.CreateDNSPolicy),
		runner.WithDisableInsecureSkipVerify(args.DisableInsecureSkipVerify),
		runner.WithSegmentsMapping(args.SegmentsMapping.String()),
		runner.WithEndpointsMapping(args.EndpointsMapping.String()),
		runner.WithInferHints(args.InferDisjointHints),
		runner.WithPolicyOptimizationLevel(args.PolicyOptimizationLevel.String()),
	)
	if err != nil {
		return err
	}
	_, err = runnerObj.Run()
	return err
}
