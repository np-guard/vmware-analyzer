package cli

import "github.com/np-guard/vmware-analyzer/pkg/runner"

const (
	cmdCollect  = "collect"
	cmdAnalyze  = "analyze"
	cmdGenerate = "generate"
	cmdLint     = "lint"
)

func runCommand(args *inArgs, cmd string) error {
	runnerObj, err := runner.NewRunnerWithOptionsList(
		runner.WithOutputFormat(args.outputFormat),
		runner.WithOutputColor(args.color),
		runner.WithHighVerbosity(args.verbose),
		runner.WithQuietVerbosity(args.quiet),
		runner.WithLogFile(args.logFile),
		runner.WithNSXURL(args.host),
		runner.WithNSXUser(args.user),
		runner.WithNSXPassword(args.password),
		runner.WithResourcesDumpFile(args.resourceDumpFile),
		runner.WithResourcesAnonymization(args.anonymize),
		runner.WithResourcesInputFile(args.resourceInputFile),
		runner.WithTopologyDumpFile(args.topologyDumpFile),
		runner.WithAnalysisOutputFile(args.outputFile),
		runner.WithAnalysisExplain(args.explain),
		runner.WithAnalysisVMsFilter(args.outputFilter),
		runner.WithSynthesisDir(args.synthesisDir),
		runner.WithSynthAdminPolicies(args.synthesizeAdmin),
		runner.WithSynthesisHints(args.disjointHints),
		runner.WithSynthDNSPolicies(args.createDNSPolicy),
		runner.WithInsecureSkipVerify(args.insecureSkipVerify),
		runner.WithSkipAnalysis(cmd != cmdAnalyze),
		runner.WithSynth(cmd == cmdGenerate),
		runner.WithLint(cmd == cmdLint),
		runner.WithSegmentsMapping(args.segmentsMapping),
		runner.WithEndpointsMapping(args.endpointsMapping),
	)
	if err != nil {
		return err
	}
	_, err = runnerObj.Run()
	return err
}
