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
	policy   []*symbolicPolicy    // with default deny
}

// Tags map from tag's name to the tag
type Tags map[string]*collector.Tag

// symbolicRule input to synthesis. Synthesis very likely to non-prioritized only allow policy
//
//nolint:all
type symbolicRule struct { // original rule
	origRule *dfw.FwRule // original rule
	// category; for reference, e.g. in the labels or documentation of the synthesized objects
	// a pass rule is interpreted as deny for the current category
	origRuleCategory  dfw.DfwCategory
	origSymbolicPaths *symbolicexpr.SymbolicPaths // symbolic presentation paths defined by the original rule
	// The following refers to conversion of original allow rule to symbolic paths, as follows:
	// Assuming there are only allow (non-prioritized, of course) policy.
	// This is relevant only for allow policy (nil otherwise)
	allowOnlyRulePaths      symbolicexpr.SymbolicPaths
	allowOnlyEffectingRules []*dfw.FwRule // policy effecting allowOnlyRulePaths (potentially higher priority pass and deny)
	// Assuming there are prioritized allow and deny policy (but no categories and pass)
	// This is relevant for allow and deny policy (pass nil), priorities are the same as of the original policy
	allowAndDenyRulesPaths     symbolicexpr.SymbolicPaths
	allowAndDenyEffectingRules []*dfw.FwRule // policy effecting allowAndDenyRulesPaths (potentially higher priority pass)
}

type symbolicPolicy struct {
	inbound  []*symbolicRule // ordered list inbound symbolicRule
	outbound []*symbolicRule // ordered list outbound symbolicRule
}

// maps used by AbstractModelSyn

// Segments topology; map from segment name to the segment
type Segments map[string]*collector.Segment

// VMs map from VM name to the VM
type VMs map[string]*endpoints.VM

func (policy symbolicPolicy) string() string {
	return "\nsymbolicInbound Rules:\n~~~~~~~~~~~~~~~~~~~~~~~\n" + strSymbolicRules(policy.inbound) +
		"\nsymbolicOutbound Rules:\n~~~~~~~~~~~~~~~~~~~~~~~~~\n" + strSymbolicRules(policy.outbound)
}

func strSymbolicRules(rules []*symbolicRule) string {
	resStr := make([]string, len(rules))
	for i, rule := range rules {
		resStr[i] = fmt.Sprintf("\tcategory: %v action: %v paths: %v", rule.origRuleCategory, rule.origRule.Action,
			rule.origSymbolicPaths)
	}
	return strings.Join(resStr, "\n")
}
