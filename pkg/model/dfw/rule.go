package dfw

import (
	"slices"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type ruleAction string

const (
	actionAllow     ruleAction = "allow"
	actionDeny      ruleAction = "deny" // currently not differentiating between "reject" and "drop"
	actionJumpToApp ruleAction = "jump_to_application"
	actionNone      ruleAction = "none" // to mark that a default rule is not configured
)

type fwRule struct {
	srcVMs []*endpoints.VM
	dstVMs []*endpoints.VM
	conn   *connection.Set
	action ruleAction
	// direction string
	// srcRuleObj ... todo: add a reference to the original rule retrieved from api
}

func (f fwRule) capturesPair(src, dst *endpoints.VM) bool {
	return slices.Contains(f.srcVMs, src) && slices.Contains(f.dstVMs, dst)
}
