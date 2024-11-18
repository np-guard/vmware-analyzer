package dfw

import (
	"fmt"
	"github.com/np-guard/vmware-analyzer/pkg/model/synthesis"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"

	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

type ruleAction string

const (
	listSeparatorStr = ","
	lineSeparatorStr = "\n"
)

/*var egressDirections = []string{"OUT", "IN_OUT"}
var ingressDirections = []string{"IN", "IN_OUT"}*/

const (
	actionAllow     ruleAction = "allow"
	actionDeny      ruleAction = "deny" // currently not differentiating between "reject" and "drop"
	actionJumpToApp ruleAction = "jump_to_application"
	actionNone      ruleAction = "none" // to mark that a default rule is not configured
)

/*func actionFromString(input string) ruleAction {
	switch input {
	case string(actionAllow):
		return actionAllow
	case string(actionDeny):
		return actionDeny
	case string(actionJumpToApp):
		return actionJumpToApp
	}
	return actionDeny
}*/

func actionFromString(s string) ruleAction {
	switch strings.ToLower(s) {
	case string(actionAllow):
		return actionAllow
	case string(actionDeny), "reject", "drop": // TODO: change
		return actionDeny
	case string(actionJumpToApp):
		return actionJumpToApp
	default:
		return actionNone
	}
}

type FwRule struct {
	srcVMs        []*endpoints.VM
	dstVMs        []*endpoints.VM
	scope         []*endpoints.VM
	conn          *netset.TransportSet
	action        ruleAction
	direction     string //	"IN","OUT",	"IN_OUT"
	origRuleObj   *collector.Rule
	ruleID        int
	secPolicyName string
	// clause of symbolic src abd symbolic dst
	// todo: in order to compute these will have to mantain and use the (not yet exported) synthesis.AbstractModelSyn.atomics
	//       keep it there?
	symbolicSrc []synthesis.SymbolicSrcDst
	symbolicDst []synthesis.SymbolicSrcDst
	// srcRuleObj ... todo: add a reference to the original rule retrieved from api
}

func (f *FwRule) effectiveRules() (inbound, outbound *FwRule) {
	if len(f.scope) == 0 {
		logging.Debugf("rule %d has no effective inbound/outbound component, since its scope component is empty", f.ruleID)
		return nil, nil
	}
	if f.conn.IsEmpty() {
		logging.Debugf("rule %d has no effective inbound/outbound component, since its traffic attributes are empty", f.ruleID)
		return nil, nil
	}
	return f.getInboundRule(), f.getOutboundRule()
}

func (f *FwRule) getInboundRule() *FwRule {
	// if action is OUT -> return nil
	if f.direction == string(nsx.RuleDirectionOUT) {
		logging.Debugf("rule %d has no effective inbound component, since its direction is OUT only", f.ruleID)
		return nil
	}
	if len(f.dstVMs) == 0 {
		logging.Debugf("rule %d has no effective inbound component, since its dest vms component is empty", f.ruleID)
		return nil
	}
	if len(f.srcVMs) == 0 {
		logging.Debugf("rule %d has no effective inbound component, since its target src vms component is empty", f.ruleID)
		return nil
	}

	// inbound rule operates on intersection(dest, scope)
	newDest := endpoints.Intersection(f.dstVMs, f.scope)
	if len(newDest) == 0 {
		logging.Debugf("rule %d has no effective inbound component, since its intersction for dest & scope is empty", f.ruleID)
		return nil
	}
	return &FwRule{
		srcVMs:        f.srcVMs,
		dstVMs:        newDest,
		conn:          f.conn,
		action:        f.action,
		direction:     string(nsx.RuleDirectionIN),
		origRuleObj:   f.origRuleObj,
		ruleID:        f.ruleID,
		secPolicyName: f.secPolicyName,
	}
}

func (f *FwRule) getOutboundRule() *FwRule {
	// if action is IN -> return nil
	if f.direction == string(nsx.RuleDirectionIN) {
		logging.Debugf("rule %d has no effective outbound component, since its direction is IN only", f.ruleID)
		return nil
	}
	if len(f.srcVMs) == 0 {
		logging.Debugf("rule %d has no effective outbound component, since its src vms component is empty", f.ruleID)
		return nil
	}

	if len(f.dstVMs) == 0 {
		logging.Debugf("rule %d has no effective outbound component, since its target dst vms component is empty", f.ruleID)
		return nil
	}

	// outbound rule operates on intersection(src, scope)
	newSrc := endpoints.Intersection(f.srcVMs, f.scope)
	if len(newSrc) == 0 {
		logging.Debugf("rule %d has no effective outbound component, since its intersction for src & scope is empty", f.ruleID)
		return nil
	}
	return &FwRule{
		srcVMs:        newSrc,
		dstVMs:        f.dstVMs,
		conn:          f.conn,
		action:        f.action,
		direction:     string(nsx.RuleDirectionOUT),
		origRuleObj:   f.origRuleObj,
		ruleID:        f.ruleID,
		secPolicyName: f.secPolicyName,
	}
}

func (f *FwRule) processedRuleCapturesPair(src, dst *endpoints.VM) bool {
	// in processed rule the src/dst vms already consider the original scope rule
	// and the separation to inound/outbound is done in advance
	return slices.Contains(f.srcVMs, src) && slices.Contains(f.dstVMs, dst)
}

// return whether the rule captures the input src,dst VMs on the given direction
/*func (f *FwRule) capturesPair(src, dst *endpoints.VM, isIngress bool) bool {
	vmsCaptured := slices.Contains(f.srcVMs, src) && slices.Contains(f.dstVMs, dst)
	if !vmsCaptured {
		return false
	}
	if isIngress {
		return slices.Contains(ingressDirections, f.direction) && slices.Contains(f.scope, dst)
	}
	return slices.Contains(egressDirections, f.direction) && slices.Contains(f.scope, src)
}*/

func vmsString(vms []*endpoints.VM) string {
	names := make([]string, len(vms))
	for i := range vms {
		names[i] = vms[i].Name()
	}
	return strings.Join(names, listSeparatorStr)
}

// return a string representation of a single rule
func (f *FwRule) string() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s, scope: %s, sec-policy: %s",
		f.ruleID, vmsString(f.srcVMs), vmsString(f.dstVMs), f.conn.String(), string(f.action), f.direction, vmsString(f.scope), f.secPolicyName)
}

func (f *FwRule) effectiveRuleStr() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s, sec-policy: %s",
		f.ruleID, vmsString(f.srcVMs), vmsString(f.dstVMs), f.conn.String(), string(f.action), f.direction, f.secPolicyName)
}
