package config

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

type SynthesisOptions struct {
	Hints                   *symbolicexpr.Hints
	InferHints              bool
	SynthesizeAdmin         bool
	Color                   bool
	CreateDNSPolicy         bool
	FilterVMs               []string
	EndpointsMapping        common.Endpoints
	SegmentsMapping         common.Segments
	PolicyOptimizationLevel common.PolicyOptimizationLevel
}

func (options *SynthesisOptions) OutputOption() *common.OutputParameters {
	return &common.OutputParameters{Color: options.Color, VMs: options.FilterVMs}
}
