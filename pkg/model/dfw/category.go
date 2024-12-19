package dfw

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
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

// allowedConns are the set of connections between src to dst, for which this category allows the netset.
// jumpToAppConns are the set of connections between src to dst, for which this category applies the rule
// action jump_to_app. notDeterminedConns are the set of connections between src to dst, for which this category
// has no verdict (no relevant rule + no default defined), thus are expected to be inspected by the next cateorgy
// (or by the "global default") if this is the last category
// todo: may possibly eliminate jumpToAppConns and unify them with notDeterminedConns
//
//nolint:gocritic // for now keep commentedOutCode
func (c *categorySpec) analyzeCategory(src, dst *endpoints.VM, isIngress bool,
) (allowedConns, jumpToAppConns, deniedConns, nonDet *netset.TransportSet) {
	allowedConns, jumpToAppConns, deniedConns = netset.NoTransports(), netset.NoTransports(), netset.NoTransports()
	rules := c.processedRules.inbound // inbound effective rules
	if !isIngress {
		rules = c.processedRules.outbound // outbound effective rules
	}
	for _, rule := range rules /*c.rules*/ {
		if rule.processedRuleCapturesPair(src, dst) /*rule.capturesPair(src, dst, isIngress)*/ {
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
		nonDet = netset.AllTransports().Subtract(allowedConns).Subtract(deniedConns).Subtract(jumpToAppConns)
	case actionAllow: // default allow
		allowedConns = netset.AllTransports().Subtract(deniedConns).Subtract(jumpToAppConns)
		nonDet = netset.NoTransports()
	case actionDeny: // default deny
		deniedConns = netset.AllTransports().Subtract(allowedConns).Subtract(jumpToAppConns)
		nonDet = netset.NoTransports()
	default:
		return nil, nil, nil, nil // invalid default action (todo: add err? )
	}
	return allowedConns, jumpToAppConns, deniedConns, nonDet
}

func (c *categorySpec) collectRelevantRules(src, dst *endpoints.VM, relevantRules *relevantRules) {
	for _, isIngress := range []bool{false, true} {
		rules := c.processedRules.inbound
		if !isIngress {
			rules = c.processedRules.outbound
		}
		for _, rule := range rules {
			if rule.processedRuleCapturesPair(src, dst) {
				switch {
				case rule.action == actionAllow && !isIngress:
					relevantRules.egressAllow = append(relevantRules.egressAllow, rule)
				case rule.action == actionDeny && !isIngress:
					relevantRules.egressDeny = append(relevantRules.egressDeny, rule)
				case rule.action == actionAllow && isIngress:
					relevantRules.ingressAllow = append(relevantRules.ingressAllow, rule)
				case rule.action == actionDeny && isIngress:
					relevantRules.ingressDeny = append(relevantRules.ingressDeny, rule)
				}
			}
		}
	}
}

func (c *categorySpec) originalRulesStr() []string {
	rulesStr := make([]string, len(c.rules))
	for i := range c.rules {
		rulesStr[i] = c.rules[i].originalRuleStr()
	}
	return rulesStr
}

func (c *categorySpec) string() string {
	rulesStr := make([]string, len(c.rules)+1)
	rulesStr[0] = "rules:"
	for i := range c.rules {
		rulesStr[i+1] = c.rules[i].string()
	}
	return fmt.Sprintf("category: %s\n%s\ndefault action: %s", c.category.string(),
		strings.Join(rulesStr, lineSeparatorStr), string(c.defaultAction))
}

func (c *categorySpec) inboundEffectiveRules() string {
	rulesStr := make([]string, len(c.processedRules.inbound))
	for i := range c.processedRules.inbound {
		rulesStr[i] = c.processedRules.inbound[i].effectiveRuleStr()
	}
	return strings.Join(rulesStr, lineSeparatorStr)
}

func (c *categorySpec) outboundEffectiveRules() string {
	rulesStr := make([]string, len(c.processedRules.outbound))
	for i := range c.processedRules.outbound {
		rulesStr[i] = c.processedRules.outbound[i].effectiveRuleStr()
	}
	return strings.Join(rulesStr, lineSeparatorStr)
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
