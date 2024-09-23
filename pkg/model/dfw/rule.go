package dfw

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type ruleAction string

const listSeparatorStr = ","
const lineSeparatorStr = "\n"

const (
	actionAllow     ruleAction = "allow"
	actionDeny      ruleAction = "deny" // currently not differentiating between "reject" and "drop"
	actionJumpToApp ruleAction = "jump_to_application"
	actionNone      ruleAction = "none" // to mark that a default rule is not configured
)

func actionFromString(input string) ruleAction {
	switch input {
	case string(actionAllow):
		return actionAllow
	case string(actionDeny):
		return actionDeny
	case string(actionJumpToApp):
		return actionJumpToApp
	}
	return actionDeny
}

type fwRule struct {
	srcVMs []*endpoints.VM
	dstVMs []*endpoints.VM
	conn   *connection.Set
	action ruleAction
	// direction string
	// srcRuleObj ... todo: add a reference to the original rule retrieved from api
}

// return whether the rule captures the input src,dst VMs
func (f *fwRule) capturesPair(src, dst *endpoints.VM) bool {
	return slices.Contains(f.srcVMs, src) && slices.Contains(f.dstVMs, dst)
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
	return fmt.Sprintf("src: %s, dst: %s, conn: %s, action: %s", vmsString(f.srcVMs), vmsString(f.dstVMs), f.conn.String(), string(f.action))
}
