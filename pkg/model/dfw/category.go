package dfw

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
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
	Category       DfwCategory
	rules          []*FwRule // ordered list of rules
	defaultAction  RuleAction
	ProcessedRules *EffectiveRules // ordered list of effective rules
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
func (c *CategorySpec) analyzeCategory(src, dst *endpoints.VM, isIngress bool,
) (allowedConns, jumpToAppConns, deniedConns, nonDet *netset.TransportSet) {
	allowedConns, jumpToAppConns, deniedConns = netset.NoTransports(), netset.NoTransports(), netset.NoTransports()
	rules := c.ProcessedRules.Inbound // inbound effective rules
	if !isIngress {
		rules = c.ProcessedRules.Outbound // outbound effective rules
	}
	for _, rule := range rules /*c.rules*/ {
		if rule.processedRuleCapturesPair(src, dst) /*rule.capturesPair(src, dst, isIngress)*/ {
			switch rule.Action {
			case actionAllow:
				addedAllowedConns := rule.Conn.Subtract(deniedConns).Subtract(jumpToAppConns)
				allowedConns = allowedConns.Union(addedAllowedConns)
			case actionDeny:
				addedDeniedConns := rule.Conn.Subtract(allowedConns).Subtract(jumpToAppConns)
				deniedConns = deniedConns.Union(addedDeniedConns)
			case actionJumpToApp:
				addedJumpToAppConns := rule.Conn.Subtract(allowedConns).Subtract(deniedConns)
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

func (c *CategorySpec) originalRulesStr() []string {
	rulesStr := make([]string, len(c.rules))
	for i := range c.rules {
		rulesStr[i] = c.rules[i].originalRuleStr()
	}
	return rulesStr
}

func (c *CategorySpec) string() string {
	rulesStr := make([]string, len(c.rules)+1)
	rulesStr[0] = "rules:"
	for i := range c.rules {
		rulesStr[i+1] = c.rules[i].string()
	}
	return fmt.Sprintf("category: %s\n%s\ndefault action: %s", c.Category.string(),
		strings.Join(rulesStr, lineSeparatorStr), string(c.defaultAction))
}

func (c *CategorySpec) inboundEffectiveRules() string {
	rulesStr := make([]string, len(c.ProcessedRules.Inbound))
	for i := range c.ProcessedRules.Inbound {
		rulesStr[i] = c.ProcessedRules.Inbound[i].effectiveRuleStr()
	}
	return strings.Join(rulesStr, lineSeparatorStr)
}

func (c *CategorySpec) outboundEffectiveRules() string {
	rulesStr := make([]string, len(c.ProcessedRules.Outbound))
	for i := range c.ProcessedRules.Outbound {
		rulesStr[i] = c.ProcessedRules.Outbound[i].effectiveRuleStr()
	}
	return strings.Join(rulesStr, lineSeparatorStr)
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
		ruleID:             ruleID,
		origRuleObj:        origRule,
		origDefaultRuleObj: origDefaultRule,
		scope:              scope,
		ScopeGroups:        scopeGroups,
		secPolicyName:      secPolicyName,
		secPolicyCategory:  c.Category.string(),
		categoryRef:        c,
		dfwRef:             c.dfwRef,
	}
	c.rules = append(c.rules, newRule)

	inbound, outbound := newRule.effectiveRules()
	if c.Category != ethernetCategory {
		c.ProcessedRules.addInboundRule(inbound)
		c.ProcessedRules.addOutboundRule(outbound)
	} else {
		logging.Debugf("rule %d in ethernet Category is ignored and not added to list of effective rules", ruleID)
	}
}

func newEmptyCategory(c DfwCategory, d *DFW) *CategorySpec {
	return &CategorySpec{
		Category:       c,
		dfwRef:         d,
		defaultAction:  actionNone,
		ProcessedRules: &EffectiveRules{},
	}
}
