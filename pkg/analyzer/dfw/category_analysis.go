package dfw

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/endpoints"
)

// analyzeCategory returns sets of connections w.r.t their determining rule action from this category rules,
// for VM connectivity from src to dst
// todo: may possibly eliminate jumpToAppConns and unify them with notDeterminedConns
//
//nolint:gocritic // temporarily keep commented-out code
func (c *CategorySpec) analyzeCategory(src, dst *endpoints.VM, isIngress bool,
) (allowedConns, // allowedConns are the set of connections between src to dst, which are allowed by this category rules.
	jumpToAppConns, // jumpToAppConns are the set of connections between src to dst, for which this category applies the
	// rule action jump_to_app.
	deniedConns, // deniedConns are the set of connections between src to dst, which are denied by this category rules.
	nonDet *connectionsAndRules, // notDeterminedConns are the set of connections between src to dst, for which this category
// has no verdict (no relevant rule + no default defined), thus are expected to be inspected by the next cateorgy
) {
	// logging.Debugf("category: %s", c.Category.String())
	allowedConns, jumpToAppConns, deniedConns = emptyConnectionsAndRules(), emptyConnectionsAndRules(), emptyConnectionsAndRules()
	rules := c.EffectiveRules.Inbound // inbound effective rules
	if !isIngress {
		rules = c.EffectiveRules.Outbound // outbound effective rules
	}
	// logging.Debugf("num of rules: %d", len(rules))
	for _, rule := range rules {
		if rule.evaluatedRuleCapturesPair(src, dst) {
			switch rule.Action {
			case ActionAllow:
				addedAllowedConns := rule.Conn.Subtract(deniedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.RuleID, Conn: addedAllowedConns.Subtract(allowedConns.accumulatedConns)}
				allowedConns.accumulatedConns = allowedConns.accumulatedConns.Union(addedAllowedConns)
				if !rulePartition.Conn.IsEmpty() {
					allowedConns.partitionsByRules = append(allowedConns.partitionsByRules, rulePartition)
				}

			case ActionDeny:
				addedDeniedConns := rule.Conn.Subtract(allowedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.RuleID, Conn: addedDeniedConns.Subtract(deniedConns.accumulatedConns)}
				deniedConns.accumulatedConns = deniedConns.accumulatedConns.Union(addedDeniedConns)
				if !rulePartition.Conn.IsEmpty() {
					deniedConns.partitionsByRules = append(deniedConns.partitionsByRules, rulePartition)
				}

			case ActionJumpToApp:
				addedJumpToAppConns := rule.Conn.Subtract(allowedConns.accumulatedConns).Subtract(deniedConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.RuleID, Conn: addedJumpToAppConns.Subtract(jumpToAppConns.accumulatedConns)}
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

type connectionsAndRules struct {
	accumulatedConns  *netset.TransportSet
	partitionsByRules []*connectivity.RuleAndConn
}

func (cr *connectionsAndRules) String() string {
	partitionsByRulesStr := common.JoinStringifiedSlice(cr.partitionsByRules, ";")
	return fmt.Sprintf("accumulatedConns: %s, partitionsByRules: %s", cr.accumulatedConns.String(), partitionsByRulesStr)
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

func (cr *connectionsAndRules) union(cr2 *connectionsAndRules) {
	cr.accumulatedConns = cr.accumulatedConns.Union(cr2.accumulatedConns)
	cr.partitionsByRules = append(cr.partitionsByRules, cr2.partitionsByRules...)
}

func emptyConnectionsAndRules() *connectionsAndRules {
	return &connectionsAndRules{
		accumulatedConns: netset.NoTransports(),
	}
}
