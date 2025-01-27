package dfw

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"

	"github.com/np-guard/vmware-analyzer/pkg/model/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// https://dp-downloads.broadcom.com/api-content/apis/API_NTDCRA_001/4.2/html/api_includes/types_SecurityPolicy.html

// EffectiveRules are built from original rules, split to separate Inbound & Outbound rules
// consider already the scope from the original rules
type EffectiveRules struct {
	Inbound  []*FwRule
	Outbound []*FwRule
}

func (e *EffectiveRules) addInboundRule(r *FwRule) {
	if r != nil {
		e.Inbound = append(e.Inbound, r)
	}
}

func (e *EffectiveRules) addOutboundRule(r *FwRule) {
	if r != nil {
		e.Outbound = append(e.Outbound, r)
	}
}

type CategorySpec struct {
	Category       collector.DfwCategory
	Rules          []*FwRule // ordered list of rules
	defaultAction  RuleAction
	ProcessedRules *EffectiveRules // ordered list of effective rules
	dfwRef         *DFW
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

// analyzeCategory returns sets of connections w.r.t their determining rule action from this category rules,
// for VM connectivity from src to dst
// todo: may possibly eliminate jumpToAppConns and unify them with notDeterminedConns
func (c *CategorySpec) analyzeCategory(src, dst *endpoints.VM, isIngress bool,
) (allowedConns, // allowedConns are the set of connections between src to dst, which are allowed by this category rules.
	jumpToAppConns, // jumpToAppConns are the set of connections between src to dst, for which this category applies the
	// rule action jump_to_app.
	deniedConns, // deniedConns are the set of connections between src to dst, which are denied by this category rules.
	nonDet *connectionsAndRules, // notDeterminedConns are the set of connections between src to dst, for which this category
// has no verdict (no relevant rule + no default defined), thus are expected to be inspected by the next cateorgy
) {
	allowedConns, jumpToAppConns, deniedConns = emptyConnectionsAndRules(), emptyConnectionsAndRules(), emptyConnectionsAndRules()
	rules := c.ProcessedRules.Inbound // inbound effective rules
	if !isIngress {
		rules = c.ProcessedRules.Outbound // outbound effective rules
	}
	for _, rule := range rules {
		if rule.processedRuleCapturesPair(src, dst) {
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
	switch c.defaultAction {
	case ActionNone: // no default configured for this category
		nonDet.accumulatedConns = netset.AllTransports().Subtract(allowedConns.accumulatedConns).Subtract(deniedConns.accumulatedConns).Subtract(
			jumpToAppConns.accumulatedConns)
	case ActionAllow: // default allow
		rulePartition := &connectivity.RuleAndConn{RuleID: 0, Conn: netset.AllTransports().Subtract(allowedConns.accumulatedConns)}
		allowedConns.accumulatedConns = netset.AllTransports().Subtract(deniedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
		nonDet.accumulatedConns = netset.NoTransports()
		if !rulePartition.Conn.IsEmpty() {
			allowedConns.partitionsByRules = append(allowedConns.partitionsByRules, rulePartition)
		}
	case ActionDeny: // default deny
		rulePartition := &connectivity.RuleAndConn{RuleID: 0, Conn: netset.AllTransports().Subtract(deniedConns.accumulatedConns)}
		deniedConns.accumulatedConns = netset.AllTransports().Subtract(allowedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
		nonDet.accumulatedConns = netset.NoTransports()
		if !rulePartition.Conn.IsEmpty() {
			deniedConns.partitionsByRules = append(deniedConns.partitionsByRules, rulePartition)
		}
	default:
		return nil, nil, nil, nil // invalid default action (todo: add err? )
	}
	return allowedConns, jumpToAppConns, deniedConns, nonDet
}

func (c *CategorySpec) originalRulesStr() []string {
	rulesStr := make([]string, len(c.Rules))
	for i := range c.Rules {
		rulesStr[i] = c.Rules[i].originalRuleStr()
	}
	return rulesStr
}

func (c *CategorySpec) String() string {
	rulesStr := common.JoinStringifiedSlice(c.Rules, lineSeparatorStr)
	return fmt.Sprintf("category: %s\nrules:\n%s\ndefault action: %s", c.Category.String(),
		rulesStr, string(c.defaultAction))
}

func (c *CategorySpec) inboundEffectiveRules() string {
	return common.JoinCustomStrFuncSlice(c.ProcessedRules.Inbound,
		func(f *FwRule) string { return f.effectiveRuleStr() },
		lineSeparatorStr)
}

func (c *CategorySpec) outboundEffectiveRules() string {
	return common.JoinCustomStrFuncSlice(c.ProcessedRules.Outbound,
		func(f *FwRule) string { return f.effectiveRuleStr() },
		lineSeparatorStr)
}

func (c *CategorySpec) addRule(src, dst []*endpoints.VM, srcGroups, dstGroups, scopeGroups []*collector.Group,
	isAllSrcGroup, isAllDstGroup bool, conn *netset.TransportSet, action, direction string, ruleID int,
	origRule *collector.Rule, scope []*endpoints.VM, secPolicyName string, origDefaultRule *collector.FirewallRule) {
	newRule := &FwRule{
		srcVMs:             src,
		dstVMs:             dst,
		SrcGroups:          srcGroups,
		IsAllSrcGroups:     isAllSrcGroup,
		DstGroups:          dstGroups,
		IsAllDstGroups:     isAllDstGroup,
		Conn:               conn,
		Action:             actionFromString(action),
		direction:          direction,
		RuleID:             ruleID,
		origRuleObj:        origRule,
		origDefaultRuleObj: origDefaultRule,
		scope:              scope,
		ScopeGroups:        scopeGroups,
		secPolicyName:      secPolicyName,
		secPolicyCategory:  c.Category.String(),
		categoryRef:        c,
		dfwRef:             c.dfwRef,
	}
	c.Rules = append(c.Rules, newRule)

	inbound, outbound := newRule.effectiveRules()
	if c.Category != collector.EthernetCategory {
		c.ProcessedRules.addInboundRule(inbound)
		c.ProcessedRules.addOutboundRule(outbound)
	} else {
		logging.Debugf("rule %d in ethernet Category is ignored and not added to list of effective rules", ruleID)
	}
}

func newEmptyCategory(c collector.DfwCategory, d *DFW) *CategorySpec {
	return &CategorySpec{
		Category:       c,
		dfwRef:         d,
		defaultAction:  ActionNone,
		ProcessedRules: &EffectiveRules{},
	}
}
