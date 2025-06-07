package common

type OutputParameters struct {
	Format   OutFormat
	FileName string
	VMs      []string
	Explain  bool
	Color    bool
}

func DefaultOutputParameters() *OutputParameters {
	var outformat OutFormat
	outformat.SetDefault()
	return &OutputParameters{Format: outformat}
}
