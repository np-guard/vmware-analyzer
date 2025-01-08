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
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

// https://dp-downloads.broadcom.com/api-content/apis/API_NTDCRA_001/4.2/html/api_includes/types_SecurityPolicy.html

type DfwCategory int

const (
	ethernetCategory DfwCategory = iota
	emergencyCategory
	infrastructureCategory
	envCategory
	appCategoty
	emptyCategory
)

const (
	EthernetStr       = "Ethernet"
	EmergencyStr      = "Emergency"
	InfrastructureStr = "Infrastructure"
	EnvironmentStr    = "Environment"
	ApplicationStr    = "Application"
	EmptyStr          = "<Empty>"
)

/*func dfwCategoryFromString(s string) DfwCategory {
	switch s {
	case EthernetStr:
		return ethernetCategory
	case EmergencyStr:
		return emergencyCategory
	case InfrastructureStr:
		return infrastructureCategory
	case EnvironmentStr:
		return envCategory
	case ApplicationStr:
		return appCategoty
	case EmptyStr:
		return emptyCategory
	default:
		return emptyCategory
	}
}*/

func (d DfwCategory) string() string {
	switch d {
	case ethernetCategory:
		return EthernetStr
	case emergencyCategory:
		return EmergencyStr
	case infrastructureCategory:
		return InfrastructureStr
	case envCategory:
		return EnvironmentStr
	case appCategoty:
		return ApplicationStr
	case emptyCategory:
		return EmptyStr
	default:
		return ""
	}
}

var categoriesList = []DfwCategory{
	ethernetCategory, emergencyCategory, infrastructureCategory, envCategory, appCategoty, emptyCategory,
}

// effectiveRules are built from original rules, split to separate inbound & outbound rules
// consider already the scope from the original rules
type effectiveRules struct {
	inbound  []*FwRule
	outbound []*FwRule
}

func (e *effectiveRules) addInboundRule(r *FwRule) {
	if r != nil {
		e.inbound = append(e.inbound, r)
	}
}

func (e *effectiveRules) addOutboundRule(r *FwRule) {
	if r != nil {
		e.outbound = append(e.outbound, r)
	}
}

type categorySpec struct {
	category       DfwCategory
	rules          []*FwRule // ordered list of rules
	defaultAction  ruleAction
	processedRules *effectiveRules // ordered list of effective rules
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
func (c *categorySpec) analyzeCategory(src, dst *endpoints.VM, isIngress bool,
) (allowedConns, // allowedConns are the set of connections between src to dst, which are allowed by this category rules.
	jumpToAppConns, // jumpToAppConns are the set of connections between src to dst, for which this category applies the
	// rule action jump_to_app.
	deniedConns, // deniedConns are the set of connections between src to dst, which are denied by this category rules.
	nonDet *connectionsAndRules, // notDeterminedConns are the set of connections between src to dst, for which this category
// has no verdict (no relevant rule + no default defined), thus are expected to be inspected by the next cateorgy
) {
	allowedConns, jumpToAppConns, deniedConns = emptyConnectionsAndRules(), emptyConnectionsAndRules(), emptyConnectionsAndRules()
	rules := c.processedRules.inbound // inbound effective rules
	if !isIngress {
		rules = c.processedRules.outbound // outbound effective rules
	}
	for _, rule := range rules {
		if rule.processedRuleCapturesPair(src, dst) {
			switch rule.action {
			case actionAllow:
				addedAllowedConns := rule.conn.Subtract(deniedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.ruleID, Conn: addedAllowedConns.Subtract(allowedConns.accumulatedConns)}
				allowedConns.accumulatedConns = allowedConns.accumulatedConns.Union(addedAllowedConns)
				if !rulePartition.Conn.IsEmpty() {
					allowedConns.partitionsByRules = append(allowedConns.partitionsByRules, rulePartition)
				}

			case actionDeny:
				addedDeniedConns := rule.conn.Subtract(allowedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.ruleID, Conn: addedDeniedConns.Subtract(deniedConns.accumulatedConns)}
				deniedConns.accumulatedConns = deniedConns.accumulatedConns.Union(addedDeniedConns)
				if !rulePartition.Conn.IsEmpty() {
					deniedConns.partitionsByRules = append(deniedConns.partitionsByRules, rulePartition)
				}

			case actionJumpToApp:
				addedJumpToAppConns := rule.conn.Subtract(allowedConns.accumulatedConns).Subtract(deniedConns.accumulatedConns)
				rulePartition := &connectivity.RuleAndConn{RuleID: rule.ruleID, Conn: addedJumpToAppConns.Subtract(jumpToAppConns.accumulatedConns)}
				jumpToAppConns.accumulatedConns = jumpToAppConns.accumulatedConns.Union(addedJumpToAppConns)
				if !rulePartition.Conn.IsEmpty() {
					jumpToAppConns.partitionsByRules = append(jumpToAppConns.partitionsByRules, rulePartition)
				}
			}
		}
	}
	nonDet = emptyConnectionsAndRules()
	switch c.defaultAction {
	case actionNone: // no default configured for this category
		nonDet.accumulatedConns = netset.AllTransports().Subtract(allowedConns.accumulatedConns).Subtract(deniedConns.accumulatedConns).Subtract(
			jumpToAppConns.accumulatedConns)
	case actionAllow: // default allow
		rulePartition := &connectivity.RuleAndConn{RuleID: 0, Conn: netset.AllTransports().Subtract(allowedConns.accumulatedConns)}
		allowedConns.accumulatedConns = netset.AllTransports().Subtract(deniedConns.accumulatedConns).Subtract(jumpToAppConns.accumulatedConns)
		nonDet.accumulatedConns = netset.NoTransports()
		if !rulePartition.Conn.IsEmpty() {
			allowedConns.partitionsByRules = append(allowedConns.partitionsByRules, rulePartition)
		}
	case actionDeny: // default deny
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

func (c *categorySpec) originalRulesStr() []string {
	rulesStr := make([]string, len(c.rules))
	for i := range c.rules {
		rulesStr[i] = c.rules[i].originalRuleStr()
	}
	return rulesStr
}

func (c *categorySpec) String() string {
	rulesStr := common.JoinStringifiedSlice(c.rules, lineSeparatorStr)
	return fmt.Sprintf("category: %s\nrules:\n%s\ndefault action: %s", c.category.string(),
		rulesStr, string(c.defaultAction))
}

func (c *categorySpec) inboundEffectiveRules() string {
	return common.JoinCustomStrFuncSlice(c.processedRules.inbound,
		func(f *FwRule) string { return f.effectiveRuleStr() },
		lineSeparatorStr)
}

func (c *categorySpec) outboundEffectiveRules() string {
	return common.JoinCustomStrFuncSlice(c.processedRules.outbound,
		func(f *FwRule) string { return f.effectiveRuleStr() },
		lineSeparatorStr)
}

func (c *categorySpec) addRule(src, dst []*endpoints.VM, conn *netset.TransportSet,
	action, direction string, ruleID int, origRule *collector.Rule, scope []*endpoints.VM,
	secPolicyName string, origDefaultRule *collector.FirewallRule) {
	newRule := &FwRule{
		srcVMs:             src,
		dstVMs:             dst,
		conn:               conn,
		action:             actionFromString(action),
		direction:          direction,
		ruleID:             ruleID,
		origRuleObj:        origRule,
		origDefaultRuleObj: origDefaultRule,
		scope:              scope,
		secPolicyName:      secPolicyName,
		secPolicyCategory:  c.category.string(),
		categoryRef:        c,
		dfwRef:             c.dfwRef,
		symbolicSrc:        []*symbolicexpr.SymbolicPath{}, // todo tmp
		symbolicDst:        []*symbolicexpr.SymbolicPath{}, // todo tmp
	}
	c.rules = append(c.rules, newRule)

	inbound, outbound := newRule.effectiveRules()
	if c.category != ethernetCategory {
		c.processedRules.addInboundRule(inbound)
		c.processedRules.addOutboundRule(outbound)
	} else {
		logging.Debugf("rule %d in ethernet category is ignored and not added to list of effective rules", ruleID)
	}
}

func newEmptyCategory(c DfwCategory, d *DFW) *categorySpec {
	return &categorySpec{
		category:       c,
		dfwRef:         d,
		defaultAction:  actionNone,
		processedRules: &effectiveRules{},
	}
}
