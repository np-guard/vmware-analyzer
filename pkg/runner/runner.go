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

	// output args
	logFile        string
	highVerobsity  bool
	outputFormat   common.OutFormat
	color          bool
	quietVerobsity bool

	// collecttor args
	nsxInsecureSkipVerify bool
	nsxURL                string
	nsxUser               string
	nsxPassword           string
	resourcesInputFile    string
	anonymize             bool
	resourcesDumpFile     string
	topologyDumpFile      string

	// analyzer args
	skipAnalysis       bool
	analysisOutputFile string
	analysisVMsFilter  []string
	analysisExplain    bool

	// synthesis args
	synth               bool
	synthesisDir        string
	disjointHints       []string
	synthesizeAdmin     bool
	suppressDNSPolicies bool
	endpointsMapping    common.Endpoints
	segmentsMapping     common.Segments

	// lint args
	lint bool

	// runner state
	nsxResources               *collector.ResourcesContainerModel
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
	verbosity := logging.MediumVerbosity
	if r.quietVerobsity {
		verbosity = logging.LowVerbosity
	} else if r.highVerobsity {
		verbosity = logging.HighVerbosity
	}
	return logging.Init(verbosity, r.logFile) // initializes a thread-safe singleton logger
}

// runCollector should assign collected NSX resources into r.resources
// (possibly with anonymization, if set true)
func (r *Runner) runCollector() error {
	if r.nsxResources != nil {
		return nil // skip collector
	}
	var err error
	if r.resourcesInputFile != "" {
		err = r.resourcesFromInputFile()
	} else {
		err = r.resourcesFromNSXEnv()
	}
	if err != nil {
		return err
	}
	if r.anonymize {
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
	if r.skipAnalysis {
		return nil
	}

	params := common.OutputParameters{
		Format:   r.outputFormat,
		FileName: r.analysisOutputFile,
		VMs:      r.analysisVMsFilter,
		Explain:  r.analysisExplain,
		Color:    r.color,
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
	if !r.lint {
		return nil
	}

	config, err := configuration.ConfigFromResourcesContainer(r.nsxResources, common.OutputParameters{Color: r.color})
	if err != nil {
		return err
	}
	lintReport := lint.LintReport(config, r.color) // currently only redundant rules analysis
	fmt.Println(lintReport)
	return nil
}

func (r *Runner) runSynthesis() error {
	if r.synthesisDir == "" && !r.synth {
		return nil
	}
	hints := &symbolicexpr.Hints{GroupsDisjoint: make([][]string, len(r.disjointHints))}
	for i, hint := range r.disjointHints {
		hints.GroupsDisjoint[i] = strings.Split(hint, common.CommaSeparator)
	}
	opts := &synth_config.SynthesisOptions{
		Hints:            hints,
		SynthesizeAdmin:  r.synthesizeAdmin,
		Color:            r.color,
		CreateDNSPolicy:  !r.suppressDNSPolicies,
		FilterVMs:        r.analysisVMsFilter,
		EndpointsMapping: r.endpointsMapping,
		SegmentsMapping:  r.segmentsMapping,
	}
	k8sResources, err := ocpvirt.NSXToK8sSynthesis(r.nsxResources, r.parsedConfig, opts)
	if err != nil {
		return err
	}
	r.generatedK8sPolicies = k8sResources.NetworkPolicies
	r.generatedK8sAdminPolicies = k8sResources.AdminNetworkPolicies
	if r.synthesisDir == "" {
		return nil
	}
	return k8sResources.WriteResourcesToDir(r.synthesisDir)
}

func (r *Runner) resourcesToFile() error {
	if r.resourcesDumpFile == "" {
		return nil
	}
	jsonString, err := r.nsxResources.ToJSONString()
	if err != nil {
		return err
	}
	return common.WriteToFile(r.resourcesDumpFile, jsonString)
}

func (r *Runner) resourcesTopologyToFile() error {
	if r.topologyDumpFile == "" {
		return nil
	}
	topology, err := r.nsxResources.OutputTopologyGraph(r.topologyDumpFile, r.outputFormat)
	if err != nil {
		return err
	}
	// TODO: remove print
	fmt.Println(topology)
	return nil
}

func (r *Runner) resourcesFromInputFile() error {
	logging.Infof("reading input NSX config file %s", r.resourcesInputFile)
	b, err := os.ReadFile(r.resourcesInputFile)
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
	server, err := collector.GetNSXServerDate(r.nsxURL, r.nsxUser, r.nsxPassword, r.nsxInsecureSkipVerify)
	if err != nil {
		return err
	}
	r.nsxResources, err = collector.CollectResources(server)
	if err != nil {
		return err
	}
	return nil
}

func NewRunnerWithOptionsList(opts ...RunnerOption) (r *Runner, err error) {
	r = &Runner{}
	// default values for enam flags
	r.outputFormat.SetDefault()
	r.endpointsMapping.SetDefault()
	r.segmentsMapping.SetDefault()
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// RunnerOption is the type for specifying options for Runner,
// using Golang's Options Pattern (https://golang.cafe/blog/golang-functional-options-pattern.html).
type RunnerOption func(*Runner)

func WithLogFile(l string) RunnerOption {
	return func(r *Runner) {
		r.logFile = l
	}
}

func WithNSXURL(l string) RunnerOption {
	return func(r *Runner) {
		r.nsxURL = l
	}
}

func WithNSXPassword(l string) RunnerOption {
	return func(r *Runner) {
		r.nsxPassword = l
	}
}

func WithNSXUser(l string) RunnerOption {
	return func(r *Runner) {
		r.nsxUser = l
	}
}

func WithHighVerbosity(verbose bool) RunnerOption {
	return func(r *Runner) {
		r.highVerobsity = verbose
	}
}

func WithQuietVerbosity(quiet bool) RunnerOption {
	return func(r *Runner) {
		r.quietVerobsity = quiet
	}
}

func WithResourcesInputFile(l string) RunnerOption {
	return func(r *Runner) {
		r.resourcesInputFile = l
	}
}

func WithResourcesAnonymization(anonymize bool) RunnerOption {
	return func(r *Runner) {
		r.anonymize = anonymize
	}
}

func WithResourcesDumpFile(l string) RunnerOption {
	return func(r *Runner) {
		r.resourcesDumpFile = l
	}
}

func WithTopologyDumpFile(l string) RunnerOption {
	return func(r *Runner) {
		r.topologyDumpFile = l
	}
}

func WithOutputFormat(l common.OutFormat) RunnerOption {
	return func(r *Runner) {
		r.outputFormat = l
	}
}

func WithSkipAnalysis(skip bool) RunnerOption {
	return func(r *Runner) {
		r.skipAnalysis = skip
	}
}

func WithAnalysisOutputFile(l string) RunnerOption {
	return func(r *Runner) {
		r.analysisOutputFile = l
	}
}

func WithOutputColor(color bool) RunnerOption {
	return func(r *Runner) {
		r.color = color
	}
}

func WithAnalysisVMsFilter(l []string) RunnerOption {
	return func(r *Runner) {
		r.analysisVMsFilter = l
	}
}

func WithAnalysisExplain(explain bool) RunnerOption {
	return func(r *Runner) {
		r.analysisExplain = explain
	}
}

func WithSynthesisDir(l string) RunnerOption {
	return func(r *Runner) {
		r.synthesisDir = l
	}
}

func WithSynthesisHints(l []string) RunnerOption {
	return func(r *Runner) {
		r.disjointHints = l
	}
}

func WithSynthAdminPolicies(enableAdmin bool) RunnerOption {
	return func(r *Runner) {
		r.synthesizeAdmin = enableAdmin
	}
}

func WithSynth(synth bool) RunnerOption {
	return func(r *Runner) {
		r.synth = synth
	}
}

func WithSynthDNSPolicies(create bool) RunnerOption {
	return func(r *Runner) {
		// create is true by default, so suppressDNSPolicies is false by default
		r.suppressDNSPolicies = !create
	}
}

// WithNSXResources will make runner skip runCollector() stage
func WithNSXResources(rc *collector.ResourcesContainerModel) RunnerOption {
	return func(r *Runner) {
		r.nsxResources = rc
	}
}

func WithInsecureSkipVerify(insecureSkipVerify bool) RunnerOption {
	return func(r *Runner) {
		r.nsxInsecureSkipVerify = insecureSkipVerify
	}
}

func WithLint(lintCmd bool) RunnerOption {
	return func(r *Runner) {
		r.lint = lintCmd
	}
}

func WithEndpointsMapping(endpoints common.Endpoints) RunnerOption {
	return func(r *Runner) {
		r.endpointsMapping = endpoints
	}
}

func WithSegmentsMapping(segments common.Segments) RunnerOption {
	return func(r *Runner) {
		r.segmentsMapping = segments
	}
}
