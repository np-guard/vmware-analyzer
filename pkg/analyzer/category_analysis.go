package analyzer

import (
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// analyzeCategory returns sets of connections w.r.t their determining rule action from this category rules,
// for VM connectivity from src to dst
// todo: may possibly eliminate jumpToAppConns and unify them with notDeterminedConns
//
//nolint:gocritic // temporarily keep commented-out code
func analyzeCategory(c *dfw.CategorySpec, src, dst topology.Endpoint, isIngress bool,
) (allowedConns, // allowedConns are the set of connections between src to dst, which are allowed by this category rules.
	jumpToAppConns, // jumpToAppConns are the set of connections between src to dst, for which this category applies the
	// rule action jump_to_app.
	deniedConns, // deniedConns are the set of connections between src to dst, which are denied by this category rules.
	nonDet *connectionsAndRules, // notDeterminedConns are the set of connections between src to dst, for which this category
// has no verdict (no relevant rule + no default defined), thus are expected to be inspected by the next cateorgy
) {
	allowedConns, jumpToAppConns, deniedConns = emptyConnectionsAndRules(), emptyConnectionsAndRules(), emptyConnectionsAndRules()
	rules := c.GetInboundEffectiveRules() // inbound effective rules
	if !isIngress {
		rules = c.GetOutboundEffectiveRules() // outbound effective rules
	}
	// logging.Debugf("num of rules: %d", len(rules))
	for _, rule := range rules {
		if rule.CapturesPair(src, dst) {
			switch rule.RuleObj.Action {
			case dfw.ActionAllow:
				addedAllowedConns := rule.RuleObj.Conn.Subtract(deniedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.RuleObj.RuleID, Conn: addedAllowedConns.Subtract(allowedConns.accumulatedConns),
					Action: dfw.ActionAllow}
				allowedConns.accumulatedConns = allowedConns.accumulatedConns.Union(addedAllowedConns)
				if !rulePartition.Conn.IsEmpty() {
					allowedConns.partitionsByRules = append(allowedConns.partitionsByRules, rulePartition)
				}

			case dfw.ActionDeny:
				addedDeniedConns := rule.RuleObj.Conn.Subtract(allowedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.RuleObj.RuleID, Conn: addedDeniedConns.Subtract(deniedConns.accumulatedConns),
					Action: dfw.ActionDeny}
				deniedConns.accumulatedConns = deniedConns.accumulatedConns.Union(addedDeniedConns)
				if !rulePartition.Conn.IsEmpty() {
					deniedConns.partitionsByRules = append(deniedConns.partitionsByRules, rulePartition)
				}

			case dfw.ActionJumpToApp:
				addedJumpToAppConns := rule.RuleObj.Conn.Subtract(allowedConns.accumulatedConns).Subtract(deniedConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.RuleObj.RuleID,
					Conn:   addedJumpToAppConns.Subtract(jumpToAppConns.accumulatedConns),
					Action: dfw.ActionJumpToApp}
				jumpToAppConns.accumulatedConns = jumpToAppConns.accumulatedConns.Union(addedJumpToAppConns)
				if !rulePartition.Conn.IsEmpty() {
					jumpToAppConns.partitionsByRules = append(jumpToAppConns.partitionsByRules, rulePartition)
				}
			}
		}
	}
	nonDet = emptyConnectionsAndRules()
	nonDet.accumulatedConns = netset.AllTransports().Subtract(allowedConns.accumulatedConns).Subtract(deniedConns.accumulatedConns).Subtract(
		jumpToAppConns.accumulatedConns) // connections not determined by this category

	return allowedConns, jumpToAppConns, deniedConns, nonDet
}

func (cr *connectionsAndRules) removeHigherPrioConnections(higherPrioConns *netset.TransportSet) {
	// complete deletion for those fully contained in higher prio conns:
	cr.partitionsByRules = slices.DeleteFunc(cr.partitionsByRules, func(n *connectivity.RuleAndConn) bool {
		return n.Conn.IsSubset(higherPrioConns)
	})
	// partial deletion for those that intersect but are not subset:
	for _, p := range cr.partitionsByRules {
		p.Conn = p.Conn.Subtract(higherPrioConns)
	}
	// clean nil entries
	newSlice := []*connectivity.RuleAndConn{}
	for _, r := range cr.partitionsByRules {
		if r != nil {
			newSlice = append(newSlice, r)
		}
	}
	cr.partitionsByRules = newSlice

	// update accumulatedConns
	cr.accumulatedConns = cr.accumulatedConns.Subtract(higherPrioConns)
}
