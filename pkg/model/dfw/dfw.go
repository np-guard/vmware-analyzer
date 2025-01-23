package dfw

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/model/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type DFW struct {
	CategoriesSpecs []*CategorySpec // ordered list of categories
	defaultAction   RuleAction      // global default (?)

	pathsToDisplayNames map[string]string // map from printing paths references as display names instead
}

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
//
//nolint:gocritic // temporarily keep commented-out code
func (d *DFW) AllowedConnections(src, dst *endpoints.VM) *connectivity.DetailedConnection {
	ingressAllowed, ingressDenied, ingressDelegated /* ingressDenied*/ := d.AllowedConnectionsIngressOrEgress(src, dst, true)
	// logging.Debugf("AllowedConnections src %s, dst %s", src.Name(), dst.Name())
	// logging.Debugf("ingressAllowed: %s", ingressAllowed.String())
	// logging.Debugf("ingressDenied: %s", ingressDenied.String())
	// logging.Debugf("ingressDelegated: %s", ingressDelegated.String())
	egressAllowed, egressDenied, egressDelegated /*egressDenied*/ := d.AllowedConnectionsIngressOrEgress(src, dst, false)
	// logging.Debugf("egressAllowed: %s", egressAllowed.String())
	// logging.Debugf("egressDenied: %s", egressDenied.String())
	// logging.Debugf("egressDelegated: %s", egressDelegated.String())

	return buildDetailedConnection(ingressAllowed, egressAllowed, ingressDenied,
		egressDenied, ingressDelegated, egressDelegated)
}

func buildDetailedConnection(ingressAllowed, egressAllowed, ingressDenied, egressDenied,
	ingressDelegated, egressDelegated *connectionsAndRules) *connectivity.DetailedConnection {
	conn := ingressAllowed.accumulatedConns.Intersect(egressAllowed.accumulatedConns)
	explanation := &connectivity.Explanation{}

	explanation.IngressExplanations = append(explanation.IngressExplanations, ingressAllowed.partitionsByRules...)
	explanation.IngressExplanations = append(explanation.IngressExplanations, ingressDenied.partitionsByRules...)
	explanation.IngressExplanations = append(explanation.IngressExplanations, ingressDelegated.partitionsByRules...)
	explanation.EgressExplanations = append(explanation.EgressExplanations, egressAllowed.partitionsByRules...)
	explanation.EgressExplanations = append(explanation.EgressExplanations, egressDenied.partitionsByRules...)
	explanation.EgressExplanations = append(explanation.EgressExplanations, egressDelegated.partitionsByRules...)

	return connectivity.NewDetailedConnection(conn, explanation)
}

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
//
//nolint:gocritic // temporarily keep commented-out code
func (d *DFW) AllowedConnectionsIngressOrEgress(src, dst *endpoints.VM, isIngress bool) (
	allAllowedConns, allDeniedConns, delegatedConns *connectionsAndRules) {
	// accumulate the following sets, from all categories - by order
	allAllowedConns = emptyConnectionsAndRules()
	allDeniedConns = emptyConnectionsAndRules()
	allNotDeterminedConns := emptyConnectionsAndRules()
	delegatedConns = emptyConnectionsAndRules()

	for _, dfwCategory := range d.CategoriesSpecs {
		if dfwCategory.Category == collector.EthernetCategory {
			continue // cuurently skip L2 rules
		}
		// get analyzed conns from this category
		categoryAllowedConns, categoryJumptToAppConns, categoryDeniedConns,
			categoryNotDeterminedConns := dfwCategory.analyzeCategory(src, dst, isIngress)
		// logging.Debugf("analyzeCategory: category %s, src %s, dst %s, isIngress %t",
		// dfwCategory.Category.String(), src.Name(), dst.Name(), isIngress)
		// logging.Debugf("categoryAllowedConns: %s", categoryAllowedConns.String())
		// logging.Debugf("categoryDeniedConns: %s", categoryDeniedConns.String())
		// logging.Debugf("categoryJumptToAppConns: %s", categoryJumptToAppConns.String())

		// remove connections already denied by higher-prio categories, from this category's allowed conns
		// categoryAllowedConns.removeHigherPrioConnections(allDeniedConns.accumulatedConns)
		categoryAllowedConns.removeHigherPrioConnections(allDeniedConns.accumulatedConns.Union(allAllowedConns.accumulatedConns))
		/*categoryAllowedConns.accumulatedConns = categoryAllowedConns.accumulatedConns.Subtract(allDeniedConns.accumulatedConns)
		// todo: delete from categoryAllowedConns.partitionsByRules the entries with connection-set contained in allDeniedConns.accumulatedConns*/

		// remove connections already allowed by higher-prio categories, from this category's denied conns
		// categoryDeniedConns.accumulatedConns = categoryDeniedConns.accumulatedConns.Subtract(allAllowedConns.accumulatedConns)
		categoryDeniedConns.removeHigherPrioConnections(allAllowedConns.accumulatedConns.Union(allDeniedConns.accumulatedConns))

		// remove connections for which there was already allow/deny by  higher-prio categories, from this category's not-determined conns
		// categoryNotDeterminedConns.accumulatedConns = categoryNotDeterminedConns.accumulatedConns.Subtract(allAllowedConns.accumulatedConns)
		// .Subtract(allDeniedConns.accumulatedConns)
		categoryNotDeterminedConns.removeHigherPrioConnections(allAllowedConns.accumulatedConns.Union(allDeniedConns.accumulatedConns))

		// remove connections for which there was already allow/deny by  higher-prio categories, from this category's JumptToApp conns
		// categoryJumptToAppConns.accumulatedConns = categoryJumptToAppConns.accumulatedConns.Subtract(allAllowedConns.accumulatedConns).
		// Subtract(allDeniedConns.accumulatedConns)
		categoryJumptToAppConns.removeHigherPrioConnections(allAllowedConns.accumulatedConns.Union(allDeniedConns.accumulatedConns))

		////////////////////////
		// update accumulated allowed, denied and not-determined conns, from current category's sets
		// allAllowedConns.accumulatedConns = allAllowedConns.accumulatedConns.Union(categoryAllowedConns.accumulatedConns)
		// logging.Debugf("allAllowedConns before: %s", allAllowedConns.String())
		allAllowedConns.union(categoryAllowedConns)
		// logging.Debugf("allAllowedConns new: %s", allAllowedConns.String())
		// todo: add to allAllowedConns.partitionsByRules the relevant partitions from this category

		// allDeniedConns.accumulatedConns = allDeniedConns.accumulatedConns.Union(categoryDeniedConns.accumulatedConns)
		// logging.Debugf("allDeniedConns before: %s", allDeniedConns.String())
		allDeniedConns.union(categoryDeniedConns)
		// logging.Debugf("allDeniedConns new: %s", allDeniedConns.String())

		// logging.Debugf("delegatedConns before: %s", delegatedConns.String())
		delegatedConns.union(categoryJumptToAppConns)
		// logging.Debugf("delegatedConns new: %s", delegatedConns.String())
		// accumulated not-determined conns: remove the conns determined from this/prev categories, and add those not-determined in this category
		allNotDeterminedConns.accumulatedConns = allNotDeterminedConns.accumulatedConns.Union(
			categoryNotDeterminedConns.accumulatedConns).Union(categoryJumptToAppConns.accumulatedConns).Subtract(
			allAllowedConns.accumulatedConns).Subtract(allDeniedConns.accumulatedConns)
	}
	// todo: add warning if there are remaining non determined connections

	if d.defaultAction == ActionAllow {
		// if the last category has no default, use the "global" default (todo: check where this value is configured in the api)
		allAllowedConns.accumulatedConns = allAllowedConns.accumulatedConns.Union(allNotDeterminedConns.accumulatedConns)
	}
	// returning the set of allowed conns from all possible categories, whether captured by explicit rules or by defaults.
	return allAllowedConns, allDeniedConns, delegatedConns
}

func (d *DFW) OriginalRulesStrFormatted() string {
	header := getRulesHeader()
	lines := [][]string{}
	for _, c := range d.CategoriesSpecs {
		lines = append(lines, c.originalRulesComponentsStr()...)
	}
	return "original rules:\n" + common.GenerateTableString(header, lines, &common.TableOptions{Colors: true})
}

// return a string rep that shows the fw-rules in all categories
func (d *DFW) String() string {
	return common.JoinStringifiedSlice(d.CategoriesSpecs, lineSeparatorStr)
}

func (d *DFW) AllEffectiveRules() string {
	inboundResStr := common.JoinCustomStrFuncSlice(d.CategoriesSpecs,
		func(c *CategorySpec) string { return c.inboundEffectiveRules() },
		lineSeparatorStr)
	outboundResStr := common.JoinCustomStrFuncSlice(d.CategoriesSpecs,
		func(c *CategorySpec) string { return c.outboundEffectiveRules() },
		lineSeparatorStr)

	inbound := fmt.Sprintf("\nInbound effective rules only:%s%s\n", common.ShortSep, inboundResStr)
	outbound := fmt.Sprintf("\nOutbound effective rules only:%s%s", common.ShortSep, outboundResStr)
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
		defaultAction: ActionDeny,
	}
	if globalDefaultAllow {
		res.defaultAction = ActionAllow
	}
	for _, c := range collector.CategoriesList {
		res.CategoriesSpecs = append(res.CategoriesSpecs, newEmptyCategory(c, res))
	}
	return res
}

func (d *DFW) GlobalDefaultAllow() bool {
	return d.defaultAction == ActionAllow
}

func (d *DFW) SetPathsToDisplayNames(m map[string]string) {
	d.pathsToDisplayNames = m
}
