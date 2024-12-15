package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

// ComputeSymbolicRules computes abstract rules in model for synthesis
// todo: will have to combine different categories into a single list of inbound, outbound
//
//nolint:all // todo: tmp for defs without implementation
func computeSymbolicRules(fireWall dfw.DFW) symbolicRules {
	_ = fireWall
	symbolicexpr.ComputeAllowGivenDenies(&symbolicexpr.SymbolicPaths{}, &symbolicexpr.SymbolicPaths{})
	return symbolicRules{nil, nil}
}
