package dfw

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type DFW struct {
	categoriesSpecs []*categorySpec // ordered list of categories
	defaultAction   ruleAction      // global default (?)

	pathsToDisplayNames map[string]string // map from printing paths references as display names instead
}

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
func (d *DFW) AllowedConnections(src, dst *endpoints.VM) *common.DetailedConnection {
	ingress := d.AllowedConnectionsIngressOrEgress(src, dst, true)
	logging.Debugf("ingress allowed connections from %s to %s: %s", src.Name(), dst.Name(), ingress.String())
	egress := d.AllowedConnectionsIngressOrEgress(src, dst, false)
	logging.Debugf("egress allowed connections from %s to %s: %s", src.Name(), dst.Name(), egress.String())
	// the set of allowed connections from src dst is the intersection of ingress & egress allowed connections
	relevantRules := &relevantRules{}
	d.collectRelevantRules(src, dst,relevantRules)
	return explain(egress, ingress, relevantRules)
}
type relevantRules struct{
	egressAllow []*FwRule
	egressDeny []*FwRule
	ingressAllow []*FwRule
	ingressDeny []*FwRule
}


type ruleAndConn struct {
	conn *netset.TransportSet
	rule int
}

func splitByRules(conn *netset.TransportSet, rules []*FwRule) []ruleAndConn {
	res := []ruleAndConn{}
	for _, rule := range rules {
		relevantConn := rule.conn.Intersect(conn)
		if !relevantConn.IsEmpty() {
			res = append(res, ruleAndConn{relevantConn, rule.ruleID})
			conn = conn.Subtract(relevantConn)
		}
	}
	return res
}

func explain(egress, ingress *netset.TransportSet,relevantRules *relevantRules) *common.DetailedConnection {
	res := common.NewDetailedConnection(ingress.Intersect(egress))
	denyEgress := netset.AllTransports().Subtract(egress)
	deniedConnsByEgress := splitByRules(denyEgress, relevantRules.egressDeny)
	for _, denyRuleAndConn := range deniedConnsByEgress {
		res.AddRuleConn(denyRuleAndConn.conn, denyRuleAndConn.rule, 0, false)
	}
	allowConnsByEgress := splitByRules(egress, relevantRules.egressAllow)
	for _, egressAllowRuleAndConn := range allowConnsByEgress {
		denyIngress := egressAllowRuleAndConn.conn.Subtract(ingress)
		deniedConnsByIngress := splitByRules(denyIngress, relevantRules.ingressDeny)
		for _, ingressDenyRuleAndConn := range deniedConnsByIngress {
			res.AddRuleConn(ingressDenyRuleAndConn.conn, egressAllowRuleAndConn.rule, ingressDenyRuleAndConn.rule, false)
		}
		allowConnsByIngress := splitByRules(egressAllowRuleAndConn.conn, relevantRules.ingressAllow)
		for _, ingressAllowRuleAndConn := range allowConnsByIngress {
			res.AddRuleConn(ingressAllowRuleAndConn.conn, egressAllowRuleAndConn.rule, ingressAllowRuleAndConn.rule, true)
		}
	}
	return res
}

func (d *DFW) collectRelevantRules(src, dst *endpoints.VM, relevantRules *relevantRules)  {
	for _, dfwCategory := range d.categoriesSpecs {
		if dfwCategory.category == ethernetCategory {
			continue // cuurently skip L2 rules
		}
		dfwCategory.collectRelevantRules(src, dst,relevantRules)
	}
}

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
func (d *DFW) AllowedConnectionsIngressOrEgress(src, dst *endpoints.VM, isIngress bool) *netset.TransportSet {
	// accumulate the following sets, from all categories - by order
	allAllowedConns := netset.NoTransports()
	allDeniedConns := netset.NoTransports()
	allNotDeterminedConns := netset.NoTransports()
	for _, dfwCategory := range d.categoriesSpecs {
		if dfwCategory.category == ethernetCategory {
			continue // cuurently skip L2 rules
		}
		// get analyzed conns from this category
		categoryAllowedConns, categoryJumptToAppConns, categoryDeniedConns,
			categoryNotDeterminedConns := dfwCategory.analyzeCategory(src, dst, isIngress)

		// remove connections already denied by higher-prio categories, from this category's allowed conns
		categoryAllowedConns = categoryAllowedConns.Subtract(allDeniedConns)
		// remove connections already allowed by higher-prio categories, from this category's denied conns
		categoryDeniedConns = categoryDeniedConns.Subtract(allAllowedConns)
		// remove connections for which there was already allow/deny by  higher-prio categories, from this category's not-determined conns
		categoryNotDeterminedConns = categoryNotDeterminedConns.Subtract(allAllowedConns).Subtract(allDeniedConns)
		// remove connections for which there was already allow/deny by  higher-prio categories, from this category's JumptToApp conns
		categoryJumptToAppConns = categoryJumptToAppConns.Subtract(allAllowedConns).Subtract(allDeniedConns)

		// update accumulated allowed, denied and not-determined conns, from current category's sets
		allAllowedConns = allAllowedConns.Union(categoryAllowedConns)
		allDeniedConns = allDeniedConns.Union(categoryDeniedConns)
		// accumulated not-determined conns: remove the conns determined from this/prev categories, and add those not-determined in this category
		allNotDeterminedConns = allNotDeterminedConns.Union(
			categoryNotDeterminedConns).Union(categoryJumptToAppConns).Subtract(
			allAllowedConns).Subtract(allDeniedConns)
	}

	if d.defaultAction == actionAllow {
		// if the last category has no default, use the "global" default (todo: check where this value is configured in the api)
		allAllowedConns = allAllowedConns.Union(allNotDeterminedConns)
	}
	// returning the set of allowed conns from all possible categories, whether captured by explicit rules or by defaults.
	return allAllowedConns
}

func (d *DFW) OriginalRulesStrFormatted() string {
	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 1, 1, 1, ' ', tabwriter.Debug)
	fmt.Fprintln(writer, "original rules:")
	fmt.Fprintln(writer, getRulesFormattedHeaderLine())
	for _, c := range d.categoriesSpecs {
		for _, ruleStr := range c.originalRulesStr() {
			if ruleStr == "" {
				continue
			}
			fmt.Fprintln(writer, ruleStr)
		}
	}
	writer.Flush()
	return builder.String()
}

// return a string rep that shows the fw-rules in all categories
func (d *DFW) String() string {
	categoriesStrings := make([]string, len(d.categoriesSpecs))
	for i := range d.categoriesSpecs {
		categoriesStrings[i] = d.categoriesSpecs[i].string()
	}
	return strings.Join(categoriesStrings, lineSeparatorStr)
}

func (d *DFW) AllEffectiveRules() string {
	inboundRes := []string{}
	outboundRes := []string{}
	for i := range d.categoriesSpecs {
		if len(d.categoriesSpecs[i].processedRules.inbound) > 0 {
			inboundRes = append(inboundRes, d.categoriesSpecs[i].inboundEffectiveRules())
		}
		if len(d.categoriesSpecs[i].processedRules.outbound) > 0 {
			outboundRes = append(outboundRes, d.categoriesSpecs[i].outboundEffectiveRules())
		}
	}
	inbound := fmt.Sprintf("\nInbound effective rules only:%s%s\n", common.ShortSep, strings.Join(inboundRes, lineSeparatorStr))
	outbound := fmt.Sprintf("\nOutbound effective rules only:%s%s", common.ShortSep, strings.Join(outboundRes, lineSeparatorStr))
	return inbound + outbound
}

// AddRule func for testing purposes

func (d *DFW) AddRule(src, dst []*endpoints.VM, conn *netset.TransportSet, categoryStr, actionStr, direction string,
	ruleID int, origRule *collector.Rule, scope []*endpoints.VM, secPolicyName string, origDefaultRule *collector.FirewallRule) {
	for _, fwCategory := range d.categoriesSpecs {
		if fwCategory.category.string() == categoryStr {
			fwCategory.addRule(src, dst, conn, actionStr, direction, ruleID, origRule, scope, secPolicyName, origDefaultRule)
		}
	}
}

/*func (d *DFW) AddRule(src, dst []*endpoints.VM, conn *netset.TransportSet, categoryStr string, actionStr string) {
	var categoryObj *categorySpec
	for _, c := range d.categoriesSpecs {
		if c.category.string() == categoryStr {
			categoryObj = c
		}
	}
	if categoryObj == nil { // create new category if missing
		categoryObj = &categorySpec{
			category: dfwCategoryFromString(categoryStr),
		}
		d.categoriesSpecs = append(d.categoriesSpecs, categoryObj)
	}

	newRule := &FwRule{
		srcVMs: src,
		dstVMs: dst,
		conn:   netset.All(), // todo: change
		action: actionFromString(actionStr),
	}
	categoryObj.rules = append(categoryObj.rules, newRule)
}*/

// NewEmptyDFW returns new DFW with global default as from input
func NewEmptyDFW(globalDefaultAllow bool) *DFW {
	res := &DFW{
		defaultAction: actionDeny,
	}
	if globalDefaultAllow {
		res.defaultAction = actionAllow
	}
	for _, c := range categoriesList {
		res.categoriesSpecs = append(res.categoriesSpecs, newEmptyCategory(c, res))
	}
	return res
}

func (d *DFW) GlobalDefaultAllow() bool {
	return d.defaultAction == actionAllow
}

func (d *DFW) SetPathsToDisplayNames(m map[string]string) {
	d.pathsToDisplayNames = m
}
