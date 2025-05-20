package common

const (
	CmdCollect  = "collect"
	CmdAnalyze  = "analyze"
	CmdGenerate = "generate"
	CmdLint     = "lint"
)

type InputArgs struct {

	// the cmd
	Cmd string

	// output options
	LogFile      string
	LogLevel     LogLevel
	Quiet        bool
	Verbose      bool
	Color        bool
	OutputFormat OutFormat

	// collecttor args
	DisableInsecureSkipVerify bool
	Host                      string
	User                      string
	Password                  string
	ResourceInputFile         string
	ResourceDumpFile          string
	TopologyDumpFile          string
	Anonymize                 bool

	// analyzer args
	OutputFile   string
	Explain      bool
	OutputFilter []string

	// synthesis args
	SynthesisDir       string
	SynthesizeAdmin    bool
	CreateDNSPolicy    bool
	DisjointHints      []string
	InferDisjointHints bool
	EndpointsMapping   Endpoints
	SegmentsMapping    Segments
}

func (args *InputArgs) SetDefault() {
	// call SetDefault() for all enum args
	args.OutputFormat.SetDefault()
	args.LogLevel.SetDefault()
	args.EndpointsMapping.SetDefault()
	args.SegmentsMapping.SetDefault()
}
