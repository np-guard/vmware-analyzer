package dfw

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type ruleAction string

const (
	listSeparatorStr = ","
	lineSeparatorStr = "\n"
)

var egressDirections = []string{"OUT", "IN_OUT"}
var ingressDirections = []string{"IN", "IN_OUT"}

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

type fwRule struct {
	srcVMs      []*endpoints.VM
	dstVMs      []*endpoints.VM
	conn        *netset.TransportSet
	action      ruleAction
	direction   string //	"IN","OUT",	"IN_OUT"
	origRuleObj *collector.Rule
	ruleID      int
	// srcRuleObj ... todo: add a reference to the original rule retrieved from api
}

// return whether the rule captures the input src,dst VMs on the given direction
func (f *fwRule) capturesPair(src, dst *endpoints.VM, isIngress bool) bool {
	vmsCaptured := slices.Contains(f.srcVMs, src) && slices.Contains(f.dstVMs, dst)
	if !vmsCaptured {
		return false
	}
	if isIngress {
		return slices.Contains(ingressDirections, f.direction)
	}
	return slices.Contains(egressDirections, f.direction)
}

func vmsString(vms []*endpoints.VM) string {
	names := make([]string, len(vms))
	for i := range vms {
		names[i] = vms[i].Name()
	}
	return strings.Join(names, listSeparatorStr)
}

// return a string representation of a single rule
func (f *fwRule) string() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s",
		f.ruleID, vmsString(f.srcVMs), vmsString(f.dstVMs), f.conn.String(), string(f.action), f.direction)
}
