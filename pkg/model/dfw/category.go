package dfw

import (
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/nsx-api-demo/pkg/model/endpoints"
)

// https://dp-downloads.broadcom.com/api-content/apis/API_NTDCRA_001/4.2/html/api_includes/types_SecurityPolicy.html

type dfwCategory int

const (
	ethernetCategory dfwCategory = iota
	emergencyCategory
	infrastructureCategory
	envCategory
	appCategoty
	emptyCategory
)

type categorySpec struct {
	category      dfwCategory
	rules         []*fwRule // ordered list of rules
	defaultAction ruleAction
}

// allowedConns are the set of connections between src to dst, for which this category allows the connection
// jumpToAppConns are the set of connections between src to dst, for which this category applies the rule action jump_to_app
// notDeterminedConns are the set of connections between src to dst, for which this category has no verdict (no relevant rule + no default defined),
// thus are expected to be inspected by the next cateorgy (or by the "global default") if this is the last category
// todo: may possibly eliminate jumpToAppConns and unify them with notDeterminedConns
func (c *categorySpec) analyzeCategory(src, dst *endpoints.VM) (allowedConns, jumpToAppConns, deniedConns, notDeterminedConns *connection.Set) {
	allowedConns, jumpToAppConns, deniedConns = connection.None(), connection.None(), connection.None()
	for _, rule := range c.rules {
		if rule.capturesPair(src, dst) {
			switch rule.action {
			case actionAllow:
				addedAllowedConns := rule.conn.Subtract(deniedConns).Subtract(jumpToAppConns)
				allowedConns = allowedConns.Union(addedAllowedConns)
			case actionDeny:
				addedDeniedConns := rule.conn.Subtract(allowedConns).Subtract(jumpToAppConns)
				deniedConns = deniedConns.Union(addedDeniedConns)
			case actionJumpToApp:
				addedJumpToAppConns := rule.conn.Subtract(allowedConns).Subtract(deniedConns)
				jumpToAppConns = jumpToAppConns.Union(addedJumpToAppConns)
			}
		}
	}
	switch c.defaultAction {
	case actionNone: // no default configured for this category
		return allowedConns, jumpToAppConns, deniedConns, connection.All().Subtract(allowedConns).Subtract(deniedConns).Subtract(jumpToAppConns)
	case actionAllow: // default allow
		return connection.All().Subtract(deniedConns).Subtract(jumpToAppConns), jumpToAppConns, deniedConns, connection.None()
	case actionDeny: // default deny
		return allowedConns, jumpToAppConns, connection.All().Subtract(allowedConns).Subtract(jumpToAppConns), connection.None()
	default:
		return nil, nil, nil, nil // invalid default action (todo: add err? )
	}
}
