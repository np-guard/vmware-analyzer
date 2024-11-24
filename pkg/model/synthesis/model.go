package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

// AbstractModelSyn is an abstraction from which the synthesis is performed
//
//nolint:all // todo: tmp for defs without implementation
type AbstractModelSyn struct {
	segments Segments
	tags     Tags // todo: should be computed by the collector or here?
	vms      VMs
	atomics  symbolicexpr.Atomics // todo: should be used and maintained by FwRule
	rules    []*symbolicRules     // with default deny
}

// Tags map from tag's name to the tag
type Tags map[string]*collector.Tag

// RuleForSynthesis input to synthesis. Synthesis very likely to non-prioritized only allow rules
//
//nolint:all // todo: tmp for defs without implementation
type RuleForSynthesis struct { // original rule
	origRule dfw.FwRule // original rule
	// category; needed for interpreting path
	// a pass rule is interpreted as deny for the current category
	category         dfw.DfwCategory
	flatSymbolicRule symbolicexpr.SymbolicPaths // symbolic paths enabled by this rule
}

//nolint:all // todo: tmp for defs without implementation
type symbolicRules struct {
	inbound  []*RuleForSynthesis // ordered list inbound RuleForSynthesis
	outbound []*RuleForSynthesis // ordered list outbound RuleForSynthesis
}

// maps used by AbstractModelSyn

// Segments topology; map from segment name to the segment
type Segments map[string]*collector.Segment

// VMs map from VM name to the VM
type VMs map[string]*endpoints.VM

// computeSymbolicRules computes abstract rules in model for synthesis
// todo: will have to combine different categories into a single list of inbound, outbound
//
//nolint:all // todo: tmp for defs without implementation
func computeSymbolicRules(fireWall dfw.DFW) symbolicRules {
	_ = fireWall
	symbolicexpr.ComputeAllowGivenDenies(symbolicexpr.SymbolicPaths{}, symbolicexpr.SymbolicPaths{})
	return symbolicRules{nil, nil}
}
