package cli

import "github.com/np-guard/vmware-analyzer/internal/common"

var args = newInArgs()

type inArgs struct {
	resourceInputFile  string
	host               string
	user               string
	password           string
	resourceDumpFile   string
	topologyDumpFile   string
	synthesisDir       string
	synthesizeAdmin    bool
	anonymize          bool
	logFile            string
	outputFile         string
	outputFormat       common.OutFormat
	quiet              bool
	verbose            bool
	explain            bool
	outputFilter       []string
	color              bool
	createDNSPolicy    bool
	disjointHints      []string
	insecureSkipVerify bool
	endpointsMapping   common.Endpoints
	segmentsMapping    common.Segments
}

func newInArgs() *inArgs {
	res := &inArgs{}
	// init enum flags with default values
	res.outputFormat.SetDefault()
	res.segmentsMapping.SetDefault()
	res.endpointsMapping.SetDefault()
	return res
}

const (
	resourceInputFileFlag       = "resource-input-file"
	hostFlag                    = "host"
	userFlag                    = "username"
	passwordFlag                = "password"
	resourceDumpFileFlag        = "resource-dump-file"
	topologyDumpFileFlag        = "topology-dump-file"
	anonymizeFlag               = "anonymize"
	synthesisDirFlag            = "synthesis-dir"
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
	insecureSkipVerifyFlag      = "insecure-skip-verify"
	endpointsMappingFlag        = "endpoints-mapping"
	segmentsMappingFlag         = "segments-mapping"

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
	synthesisDirHelp            = "run synthesis; specify directory path to store target synthesis resources"
	synthesizeAdminPoliciesHelp = "include admin network policies in policy synthesis (default false)"
	outputFormatHelp            = "output format; must be one of "
	outputFilterFlagHelp        = "filter the analysis/synthesis results by vm names, can specify more than one (example: \"vm1,vm2\")"
	quietHelp                   = "flag to run quietly, report only severe errors and result (default false)"
	verboseHelp                 = "flag to run with more informative messages printed to log (default false)"
	colorHelp                   = "flag to enable color output (default false)"
	createDNSPolicyHelp         = "flag to create a policy allowing access to target env dns pod"
	synthHelp                   = "flag to run synthesis, even if synthesis-dir is not specified"
	insecureSkipVerifyHelp      = "flag to enable NSX connection with insecureSkipVerify (default false)." +
		"Alternatively, set the NSX_SKIP_VERIFY environment variable to true"
	disjointHintsHelp = "comma separated list of NSX groups/tags that are always disjoint in their VM members," +
		" needed for an effective and sound synthesis process, can specify more than one hint" +
		" (example: \"--" + disjointHintsFlag + " frontend,backend --" + disjointHintsFlag + " app,web,db\")"
	endpointsMappingFlagHelp = "flag to set target endpoints for synthesis;  must be one of "
	segmentsMappingFlagHelp  = "flag to set target mapping from segments; must be one of "
)
