package runner

import (
	"fmt"
	"os"
	"strings"

	v1 "k8s.io/api/networking/v1"
	v1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	analyzer "github.com/np-guard/vmware-analyzer/pkg/analyzer"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/collector/anonymizer"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/lint"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	synth_config "github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt"
)

// Runner provides API to run NSX collection / analysis / synthesis operations.
type Runner struct {
	args *common.InputArgs
	/*
		// output args
		logFile        string
		logLevel       *common.LogLevel
		highVerobsity  bool
		outputFormat   *common.OutFormat
		color          bool
		quietVerobsity bool

		// collecttor args
		disableInsecureSkipVerify bool
		nsxURL                    string
		nsxUser                   string
		nsxPassword               string
		resourcesInputFile        string
		anonymize                 bool
		resourcesDumpFile         string
		topologyDumpFile          string

		// analyzer args
		skipAnalysis       bool
		analysisOutputFile string
		analysisVMsFilter  []string
		analysisExplain    bool

		// synthesis args
		synth             bool
		synthesisDir      string
		disjointHints     []string
		inferHints        bool
		synthesizeAdmin   bool
		createDNSPolicies bool
		endpointsMapping  *common.Endpoints
		segmentsMapping   *common.Segments

		// lint args
		lint bool*/

	// runner state
	nsxResources *collector.ResourcesContainerModel // can be given as input..

	// runner objects holding results
	generatedK8sPolicies       []*v1.NetworkPolicy
	generatedK8sAdminPolicies  []*v1alpha1.AdminNetworkPolicy
	connectivityAnalysisOutput string
	analyzedConnectivity       connectivity.ConnMap
	parsedConfig               *configuration.Config
}

func (r *Runner) GetGeneratedPolicies() ([]*v1.NetworkPolicy, []*v1alpha1.AdminNetworkPolicy) {
	return r.generatedK8sPolicies, r.generatedK8sAdminPolicies
}

func (r *Runner) GetConnectivityOutput() string {
	return r.connectivityAnalysisOutput
}

func (r *Runner) GetAnalyzedConnectivity() connectivity.ConnMap {
	return r.analyzedConnectivity
}

// Run executes collector/analysis/synthesis components, and returns Observations objects
func (r *Runner) Run() (*Observations, error) {
	if err := r.initLogger(); err != nil {
		return nil, err
	}
	if err := r.runCollector(); err != nil {
		return nil, err
	}
	if err := r.runAnalyzer(); err != nil {
		return nil, err
	}
	if err := r.runLint(); err != nil {
		return nil, err
	}
	if err := r.runSynthesis(); err != nil {
		return nil, err
	}
	return &Observations{r}, nil
}

func (r *Runner) initLogger() error {
	if r.args.Quiet {
		r.args.LogLevel = common.LogLevelFatal
	}
	if r.args.Verbose {
		r.args.LogLevel = common.LogLevelInfo // debug levels should be used explicitly
	}
	return logging.Init(r.args.LogLevel, r.args.LogFile)
}

// runCollector should assign collected NSX resources into r.resources
// (possibly with anonymization, if set true)
func (r *Runner) runCollector() error {
	if r.nsxResources != nil {
		return nil // skip collector
	}
	var err error
	if r.args.ResourceInputFile != "" {
		err = r.resourcesFromInputFile()
	} else {
		err = r.resourcesFromNSXEnv()
	}
	if err != nil {
		return err
	}
	if r.args.Anonymize {
		if err := anonymizer.AnonymizeNsx(r.nsxResources); err != nil {
			return err
		}
	}
	if err := r.resourcesToFile(); err != nil {
		return err
	}
	return r.resourcesTopologyToFile()
}

func (r *Runner) runAnalyzer() error {
	if r.args.Cmd != common.CmdAnalyze {
		return nil
	}

	params := common.OutputParameters{
		Format:   r.args.OutputFormat,
		FileName: r.args.OutputFile,
		VMs:      r.args.OutputFilter,
		Explain:  r.args.Explain,
		Color:    r.args.Color,
	}

	logging.Infof("starting connectivity analysis")
	parsedConfig, connMap, connResStr, err := analyzer.NSXConnectivityFromResourcesContainer(r.nsxResources, params)
	if err != nil {
		return err
	}
	r.connectivityAnalysisOutput = connResStr
	r.analyzedConnectivity = connMap
	r.parsedConfig = parsedConfig
	// TODO: remove print?
	fmt.Println(connResStr)

	return nil
}

func (r *Runner) runLint() error {
	if r.args.Cmd != common.CmdLint {
		return nil
	}

	config, err := configuration.ConfigFromResourcesContainer(r.nsxResources, common.OutputParameters{Color: r.args.Color})
	if err != nil {
		return err
	}
	lintReport := lint.LintReport(config, r.args.Color) // currently only redundant rules analysis
	fmt.Println(lintReport)
	return nil
}

func (r *Runner) runSynthesis() error {
	if r.args.Cmd != common.CmdGenerate {
		return nil
	}
	hints := &symbolicexpr.Hints{GroupsDisjoint: make([][]string, len(r.args.DisjointHints))}
	for i, hint := range r.args.DisjointHints {
		hints.GroupsDisjoint[i] = strings.Split(hint, common.CommaSeparator)
	}
	opts := &synth_config.SynthesisOptions{
		Hints:            hints,
		InferHints:       r.args.InferDisjointHints,
		SynthesizeAdmin:  r.args.SynthesizeAdmin,
		Color:            r.args.Color,
		CreateDNSPolicy:  r.args.CreateDNSPolicy,
		FilterVMs:        r.args.OutputFilter,
		EndpointsMapping: r.args.EndpointsMapping,
		SegmentsMapping:  r.args.SegmentsMapping,
	}
	k8sResources, err := ocpvirt.NSXToK8sSynthesis(r.nsxResources, r.parsedConfig, opts)
	if err != nil {
		return err
	}
	r.generatedK8sPolicies = k8sResources.NetworkPolicies
	r.generatedK8sAdminPolicies = k8sResources.AdminNetworkPolicies
	if r.args.SynthesisDir == "" {
		return nil
	}
	return k8sResources.WriteResourcesToDir(r.args.SynthesisDir)
}

func (r *Runner) resourcesToFile() error {
	if r.args.ResourceDumpFile == "" {
		return nil
	}
	jsonString, err := r.nsxResources.ToJSONString()
	if err != nil {
		return err
	}
	return common.WriteToFile(r.args.ResourceDumpFile, jsonString)
}

func (r *Runner) resourcesTopologyToFile() error {
	if r.args.TopologyDumpFile == "" {
		return nil
	}
	topology, err := r.nsxResources.OutputTopologyGraph(r.args.TopologyDumpFile, r.args.OutputFormat)
	if err != nil {
		return err
	}
	// TODO: remove print
	fmt.Println(topology)
	return nil
}

func (r *Runner) resourcesFromInputFile() error {
	logging.Infof("reading input NSX config file %s", r.args.ResourceInputFile)
	b, err := os.ReadFile(r.args.ResourceInputFile)
	if err != nil {
		return err
	}
	r.nsxResources, err = collector.FromJSONString(b)
	if err != nil {
		return err
	}
	return nil
}

func (r *Runner) resourcesFromNSXEnv() error {
	server, err := collector.GetNSXServerDate(r.args.Host, r.args.User, r.args.Password, r.args.DisableInsecureSkipVerify)
	if err != nil {
		return err
	}
	r.nsxResources, err = collector.CollectResources(server)
	if err != nil {
		return err
	}
	return nil
}

func newDefaultRunner() *Runner {
	r := Runner{
		args: &common.InputArgs{},
	}
	r.args.SetDefault()
	return &r
}

func NewRunnerWithOptionsList(opts ...RunnerOption) (r *Runner, err error) {
	r = newDefaultRunner()
	for _, o := range opts {
		if err := o(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// RunnerOption is the type for specifying options for Runner,
// using Golang's Options Pattern (https://golang.cafe/blog/golang-functional-options-pattern.html).
type RunnerOption func(*Runner) error

func WithCmd(c string) RunnerOption {
	return func(r *Runner) error {
		switch c {
		case common.CmdAnalyze, common.CmdCollect, common.CmdLint, common.CmdGenerate:
			r.args.Cmd = c
		default:
			return fmt.Errorf("unknown command: %s", c)
		}
		return nil
	}
}

func WithLogFile(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.LogFile = l
		return nil
	}
}

func WithLogLevel(l string) RunnerOption {
	return func(r *Runner) error {
		var logLevel common.LogLevel
		if err := logLevel.Set(l); err != nil {
			return err
		}
		r.args.LogLevel = logLevel
		return nil
	}
}

func WithNSXURL(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.Host = l
		return nil
	}
}

func WithNSXPassword(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.Password = l
		return nil
	}
}

func WithNSXUser(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.User = l
		return nil
	}
}

func WithHighVerbosity(verbose bool) RunnerOption {
	return func(r *Runner) error {
		r.args.Verbose = verbose
		return nil
	}
}

func WithQuietVerbosity(quiet bool) RunnerOption {
	return func(r *Runner) error {
		r.args.Quiet = quiet
		return nil
	}
}

func WithResourcesInputFile(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.ResourceInputFile = l
		return nil
	}
}

func WithResourcesAnonymization(anonymize bool) RunnerOption {
	return func(r *Runner) error {
		r.args.Anonymize = anonymize
		return nil
	}
}

func WithResourcesDumpFile(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.ResourceDumpFile = l
		return nil
	}
}

func WithTopologyDumpFile(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.TopologyDumpFile = l
		return nil
	}
}

func WithOutputFormat(l string) RunnerOption {
	return func(r *Runner) error {
		var f common.OutFormat
		if err := f.Set(l); err != nil {
			return err
		}
		r.args.OutputFormat = f
		return nil
	}
}

func WithAnalysisOutputFile(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.OutputFile = l
		return nil
	}
}

func WithOutputColor(color bool) RunnerOption {
	return func(r *Runner) error {
		r.args.Color = color
		return nil
	}
}

func WithAnalysisVMsFilter(l []string) RunnerOption {
	return func(r *Runner) error {
		r.args.OutputFilter = l
		return nil
	}
}

func WithAnalysisExplain(explain bool) RunnerOption {
	return func(r *Runner) error {
		r.args.Explain = explain
		return nil
	}
}

func WithSynthesisDir(l string) RunnerOption {
	return func(r *Runner) error {
		r.args.SynthesisDir = l
		return nil
	}
}

func WithSynthesisHints(l []string) RunnerOption {
	return func(r *Runner) error {
		r.args.DisjointHints = l
		return nil
	}
}

func WithSynthAdminPolicies(enableAdmin bool) RunnerOption {
	return func(r *Runner) error {
		r.args.SynthesizeAdmin = enableAdmin
		return nil
	}
}

func WithSynthDNSPolicies(create bool) RunnerOption {
	return func(r *Runner) error {
		r.args.CreateDNSPolicy = create
		return nil
	}
}

// WithNSXResources will make runner skip runCollector() stage
func WithNSXResources(rc *collector.ResourcesContainerModel) RunnerOption {
	return func(r *Runner) error {
		r.nsxResources = rc
		return nil
	}
}

func WithDisableInsecureSkipVerify(disableInsecureSkipVerify bool) RunnerOption {
	return func(r *Runner) error {
		r.args.DisableInsecureSkipVerify = disableInsecureSkipVerify
		return nil
	}
}

func WithEndpointsMapping(endpoints string) RunnerOption {
	return func(r *Runner) error {
		var endpointsValue common.Endpoints
		if err := endpointsValue.Set(endpoints); err != nil {
			return err
		}
		r.args.EndpointsMapping = endpointsValue
		return nil
	}
}

func WithSegmentsMapping(segments string) RunnerOption {
	return func(r *Runner) error {
		var segmentsValue common.Segments
		if err := segmentsValue.Set(segments); err != nil {
			return err
		}
		r.args.SegmentsMapping = segmentsValue
		return nil
	}
}

func WithInferHints(inferHints bool) RunnerOption {
	return func(r *Runner) error {
		r.args.InferDisjointHints = inferHints
		return nil
	}
}
