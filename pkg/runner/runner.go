package runner

import (
	"fmt"
	"os"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/anonymizer"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis"
)

// Runner provides API to run NSX collection / analysis / synthesis operations.
type Runner struct {

	// output args
	logFile        string
	highVerobsity  bool
	outputFormat   string
	color          bool
	quietVerobsity bool

	// collecttor args
	nsxURL             string
	nsxUser            string
	nsxPassword        string
	resourcesInputFile string
	anonymize          bool
	resourcesDumpFile  string
	topologyDumpFile   string

	// analyzer args
	skipAnalysis       bool
	analysisOutputFile string
	analysisVMsFilter  []string
	analysisExplain    bool

	// synthesis args
	synthesisDumpDir string
	disjointHints    []string
	synthesizeAdmin  bool

	// runner state
	resources *collector.ResourcesContainerModel
}

func (r *Runner) Run() error {
	if err := r.initLogger(); err != nil {
		return err
	}
	if err := r.runCollector(); err != nil {
		return err
	}
	if err := r.runAnalyzer(); err != nil {
		return err
	}
	if err := r.runSynthesis(); err != nil {
		return err
	}
	return nil
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
		if err := anonymizer.AnonymizeNsx(r.resources); err != nil {
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
	connResStr, err := model.NSXConnectivityFromResourcesContainer(r.resources, params)
	if err != nil {
		return err
	}
	// TODO: remove print?
	fmt.Println(connResStr)

	return nil
}

func (r *Runner) runSynthesis() error {
	if r.synthesisDumpDir == "" {
		return nil
	}
	hints := &symbolicexpr.Hints{GroupsDisjoint: make([][]string, len(r.disjointHints))}
	for i, hint := range r.disjointHints {
		hints.GroupsDisjoint[i] = strings.Split(hint, common.CommaSeparator)
	}
	k8sResources, err := synthesis.NSXToK8sSynthesis(r.resources, hints, r.synthesizeAdmin, r.color)
	if err != nil {
		return err
	}
	return k8sResources.CreateDir(r.synthesisDumpDir)
}

func (r *Runner) resourcesToFile() error {
	if r.resourcesDumpFile == "" {
		return nil
	}
	jsonString, err := r.resources.ToJSONString()
	if err != nil {
		return err
	}
	return common.WriteToFile(r.resourcesDumpFile, jsonString)
}

func (r *Runner) resourcesTopologyToFile() error {
	if r.topologyDumpFile == "" {
		return nil
	}
	topology, err := r.resources.OutputTopologyGraph(r.topologyDumpFile, r.outputFormat)
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
	r.resources, err = collector.FromJSONString(b)
	if err != nil {
		return err
	}
	return nil
}

func (r *Runner) resourcesFromNSXEnv() error {
	server, err := collector.GetNSXServerDate(r.nsxURL, r.nsxUser, r.nsxPassword)
	if err != nil {
		return err
	}
	r.resources, err = collector.CollectResources(server)
	if err != nil {
		return err
	}
	return nil
}

func NewRunnerWithOptionsList(opts ...RunnerOption) (r *Runner, err error) {
	r = &Runner{}
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

func WithOutputFormat(l string) RunnerOption {
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

func WithSynthesisDumpDir(l string) RunnerOption {
	return func(r *Runner) {
		r.synthesisDumpDir = l
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
