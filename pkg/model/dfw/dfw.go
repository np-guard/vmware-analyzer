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
	CategoriesSpecs []*CategorySpec // ordered list of categories
	defaultAction   RuleAction      // global default (?)

	pathsToDisplayNames map[string]string // map from printing paths references as display names instead
}

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
func (d *DFW) AllowedConnections(src, dst *endpoints.VM) *netset.TransportSet {
	ingress := d.AllowedConnectionsIngressOrEgress(src, dst, true)
	logging.Debugf("ingress allowed connections from %s to %s: %s", src.Name(), dst.Name(), ingress.String())
	egress := d.AllowedConnectionsIngressOrEgress(src, dst, false)
	logging.Debugf("egress allowed connections from %s to %s: %s", src.Name(), dst.Name(), egress.String())
	// the set of allowed connections from src dst is the intersection of ingress & egress allowed connections
	return ingress.Intersect(egress)
}

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
func (d *DFW) AllowedConnectionsIngressOrEgress(src, dst *endpoints.VM, isIngress bool) *netset.TransportSet {
	// accumulate the following sets, from all categories - by order
	allAllowedConns := netset.NoTransports()
	allDeniedConns := netset.NoTransports()
	allNotDeterminedConns := netset.NoTransports()

	for _, dfwCategory := range d.CategoriesSpecs {
		if dfwCategory.Category == ethernetCategory {
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
	for _, c := range d.CategoriesSpecs {
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
	categoriesStrings := make([]string, len(d.CategoriesSpecs))
	for i := range d.CategoriesSpecs {
		categoriesStrings[i] = d.CategoriesSpecs[i].string()
	}
	return strings.Join(categoriesStrings, lineSeparatorStr)
}

func (d *DFW) AllEffectiveRules() string {
	inboundRes := []string{}
	outboundRes := []string{}
	for i := range d.CategoriesSpecs {
		if len(d.CategoriesSpecs[i].ProcessedRules.Inbound) > 0 {
			inboundRes = append(inboundRes, d.CategoriesSpecs[i].inboundEffectiveRules())
		}
		if len(d.CategoriesSpecs[i].ProcessedRules.Outbound) > 0 {
			outboundRes = append(outboundRes, d.CategoriesSpecs[i].outboundEffectiveRules())
		}
	}
	inbound := fmt.Sprintf("\nInbound effective rules only:%s%s\n", common.ShortSep, strings.Join(inboundRes, lineSeparatorStr))
	outbound := fmt.Sprintf("\nOutbound effective rules only:%s%s", common.ShortSep, strings.Join(outboundRes, lineSeparatorStr))
	return inbound + outbound
}

// AddRule func for testing purposes

func (d *DFW) AddRule(src, dst []*endpoints.VM, srcGroups, dstGroups, scopeGroups []*collector.Group,
	isAllSrcGroups, isAllDstGroups bool, conn *netset.TransportSet, categoryStr, actionStr, direction string,
	ruleID int, origRule *collector.Rule, scope []*endpoints.VM, secPolicyName string, origDefaultRule *collector.FirewallRule) {
	for _, fwCategory := range d.CategoriesSpecs {
		if fwCategory.Category.String() == categoryStr {
			fwCategory.addRule(src, dst, srcGroups, dstGroups, scopeGroups, isAllSrcGroups, isAllDstGroups, conn,
				actionStr, direction, ruleID, origRule, scope, secPolicyName, origDefaultRule)
		}
	}
}

/*func (d *DFW) AddRule(src, dst []*endpoints.VM, conn *netset.TransportSet, categoryStr string, actionStr string) {
	var categoryObj *CategorySpec
	for _, c := range d.CategoriesSpecs {
		if c.Category.string() == categoryStr {
			categoryObj = c
		}
	}
	if categoryObj == nil { // create new Category if missing
		categoryObj = &CategorySpec{
			Category: dfwCategoryFromString(categoryStr),
		}
		d.CategoriesSpecs = append(d.CategoriesSpecs, categoryObj)
	}

	newRule := &FwRule{
		srcVMs: src,
		dstVMs: dst,
		Conn:   netset.All(), // todo: change
		Action: actionFromString(actionStr),
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
		res.CategoriesSpecs = append(res.CategoriesSpecs, newEmptyCategory(c, res))
	}
	return res
}

func (d *DFW) GlobalDefaultAllow() bool {
	return d.defaultAction == actionAllow
}

func (d *DFW) SetPathsToDisplayNames(m map[string]string) {
	d.pathsToDisplayNames = m
}
