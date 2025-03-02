package analyzer

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
//
//nolint:gocritic // temporarily keep commented-out code
func dfwAllowedConnections(d *dfw.DFW, src, dst topology.Endpoint) *connectivity.DetailedConnection {
	ingressAllowed, ingressDenied, ingressDelegated /* ingressDenied*/ := dfwAllowedConnectionsIngressOrEgress(d, src, dst, true)
	// logging.Debugf("AllowedConnections src %s, dst %s", src.Name(), dst.Name())
	// logging.Debugf("ingressAllowed: %s", ingressAllowed.String())
	// logging.Debugf("ingressDenied: %s", ingressDenied.String())
	// logging.Debugf("ingressDelegated: %s", ingressDelegated.String())
	egressAllowed, egressDenied, egressDelegated /*egressDenied*/ := dfwAllowedConnectionsIngressOrEgress(d, src, dst, false)
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
func dfwAllowedConnectionsIngressOrEgress(d *dfw.DFW, src, dst topology.Endpoint, isIngress bool) (
	allAllowedConns, allDeniedConns, delegatedConns *connectionsAndRules) {
	// accumulate the following sets, from all categories - by order
	allAllowedConns = emptyConnectionsAndRules()
	allDeniedConns = emptyConnectionsAndRules()
	allNotDeterminedConns := emptyConnectionsAndRules()
	delegatedConns = emptyConnectionsAndRules()
	remainingRulesNum := d.TotalEffectiveEgressRules
	if isIngress {
		remainingRulesNum = d.TotalEffectiveIngressRules
	}

	for _, dfwCategory := range d.CategoriesSpecs {
		if dfwCategory.Category == collector.EthernetCategory {
			continue // cuurently skip L2 rules
		}
		// if all connections were determined so far - no need to continue to next category
		if allNotDeterminedConns.accumulatedConns.IsEmpty() &&
			(allAllowedConns.accumulatedConns.Union(allDeniedConns.accumulatedConns)).Equal(netset.AllTransports()) {
			// add this message only if next categoires have rules that are skipped (redundant)
			if remainingRulesNum > 0 {
				logging.Debugf(
					"for src=%s, dst=%s, isIngress=%t, skipping analysis from category %s, all connections were determined by previous categories",
					src.Name(), dst.Name(), isIngress, dfwCategory.Category.String())
			}
			break
		}

		// get analyzed conns from this category
		categoryAllowedConns, categoryJumptToAppConns, categoryDeniedConns,
			categoryNotDeterminedConns := analyzeCategory(dfwCategory, src, dst, isIngress)

		// update counter of total remaining rules to analyze
		if isIngress {
			remainingRulesNum -= len(dfwCategory.EffectiveRules.Inbound)
		} else {
			remainingRulesNum -= len(dfwCategory.EffectiveRules.Outbound)
		}

		// logging.Debugf("analyzeCategory: category %s, src %s, dst %s, isIngress %t",
		//	dfwCategory.Category.String(), src.Name(), dst.Name(), isIngress)
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
		// logging.Debugf("categoryNotDeterminedConns.accumulatedConns: %s", categoryNotDeterminedConns.accumulatedConns.String())
	}
	// todo: add warning if there are remaining non determined connections

	// TODO: add test and issue warning on allNotDeterminedConns.accumulatedConns if there is no defaule rule in last category
	if !allNotDeterminedConns.accumulatedConns.IsEmpty() {
		// logging.Debugf("allNotDeterminedConns.accumulatedConns: %s", allNotDeterminedConns.accumulatedConns.String())
		logging.Debugf("no default rule - unexpected connections for which no decision was found: %s",
			allNotDeterminedConns.accumulatedConns.String())
	}
	// returning the set of allowed conns from all possible categories, whether captured by explicit rules or by defaults.
	return allAllowedConns, allDeniedConns, delegatedConns
}
