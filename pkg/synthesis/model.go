package synthesis

import (
	"fmt"
	"strings"

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

// SymbolicRule input to synthesis. Synthesis very likely to non-prioritized only allow rules
//
//nolint:all
type SymbolicRule struct { // original rule
	origRule *dfw.FwRule // original rule
	// category; for reference, e.g. in the labels or documentation of the synthesized objects
	// a pass rule is interpreted as deny for the current category
	origRuleCategory  dfw.DfwCategory
	origSymbolicPaths *symbolicexpr.SymbolicPaths // symbolic presentation paths defined by the original rule
	// The following refers to conversion of original allow rule to symbolic paths, as follows:
	// Assuming there are only allow (non-prioritized, of course) rules.
	// This is relevant only for allow rules (nil otherwise)
	allowOnlyRulePaths      symbolicexpr.SymbolicPaths
	allowOnlyEffectingRules []*dfw.FwRule // rules effecting allowOnlyRulePaths (potentially higher priority pass and deny)
	// Assuming there are prioritized allow and deny rules (but no categories and pass)
	// This is relevant for allow and deny rules (pass nil), priorities are the same as of the original rules
	allowAndDenyRulesPaths     symbolicexpr.SymbolicPaths
	allowAndDenyEffectingRules []*dfw.FwRule // rules effecting allowAndDenyRulesPaths (potentially higher priority pass)
}

//nolint:all // todo: tmp for defs without implementation
type symbolicRules struct {
	inbound  []*SymbolicRule // ordered list inbound SymbolicRule
	outbound []*SymbolicRule // ordered list outbound SymbolicRule
}

// maps used by AbstractModelSyn

// Segments topology; map from segment name to the segment
type Segments map[string]*collector.Segment

// VMs map from VM name to the VM
type VMs map[string]*endpoints.VM

func (allRules symbolicRules) string() string {
	return "\nsymbolicInbound Rules:\n~~~~~~~~~~~~~~~~~~~~~~~\n" + strSymbolicRules(allRules.inbound) +
		"\nsymbolicOutbound Rules:\n~~~~~~~~~~~~~~~~~~~~~~~~~\n" + strSymbolicRules(allRules.outbound)
}

func strSymbolicRules(rules []*SymbolicRule) string {
	resStr := make([]string, len(rules))
	for i, rule := range rules {
		resStr[i] = fmt.Sprintf("\tcategory: %v action: %v paths: %v", rule.origRuleCategory, rule.origRule.Action,
			rule.origSymbolicPaths)
	}
	return strings.Join(resStr, "\n")
}
