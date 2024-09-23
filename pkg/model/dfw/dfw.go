package dfw

import (
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

type DFW struct {
	categoriesSpecs []*categorySpec // ordered list of categories
	defaultAction   ruleAction      // global default (?)
}

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
func (d *DFW) AllowedConnections(src, dst *endpoints.VM) (allowedConns *connection.Set) {
	ingress := d.AllowedConnectionsIngressOrEgress(src, dst, true)
	egress := d.AllowedConnectionsIngressOrEgress(src, dst, false)
	// the set of allowed connections from src dst is the intersection of ingress & egress allowed connections
	return ingress.Intersect(egress)
}

// AllowedConnections computes for a pair of vms (src,dst), the set of allowed connections
func (d *DFW) AllowedConnectionsIngressOrEgress(src, dst *endpoints.VM, isIngress bool) (allowedConns *connection.Set) {
	// accumulate the following sets, from all categories - by order
	allAllowedConns := connection.None()
	allDeniedConns := connection.None()
	allNotDeterminedConns := connection.None()

	for _, dfwCategory := range d.categoriesSpecs {
		if dfwCategory.category == ethernetCategory {
			continue // cuurently skip L2 rules
		}
		// get analyzed conns from this category
		categoryAllowedConns, categoryJumptToAppConns, categoryDeniedConns, categoryNotDeterminedConns := dfwCategory.analyzeCategory(src, dst, isIngress)

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
		allNotDeterminedConns = allNotDeterminedConns.Union(categoryNotDeterminedConns).Union(categoryJumptToAppConns).Subtract(allAllowedConns).Subtract(allDeniedConns)
	}

	if d.defaultAction == actionAllow {
		// if the last category has no default, use the "global" default (todo: check where this value is configured in the api)
		allAllowedConns = allAllowedConns.Union(allNotDeterminedConns)
	}
	// returning the set of allowed conns from all possible categories, whether captured by explicit rules or by defaults.
	return allAllowedConns
}

// return a string rep that shows the fw-rules in all categories
func (d *DFW) String() string {
	categoriesStrings := make([]string, len(d.categoriesSpecs))
	for i := range d.categoriesSpecs {
		categoriesStrings[i] = d.categoriesSpecs[i].string()
	}
	return strings.Join(categoriesStrings, lineSeparatorStr)
}

// AddRule func for testing purposes

func (d *DFW) AddRule(src, dst []*endpoints.VM, conn *connection.Set, categoryStr string, actionStr string, direction string, origRule *nsx.Rule) {
	for _, fwCategory := range d.categoriesSpecs {
		if fwCategory.category.string() == categoryStr {
			fwCategory.addRule(src, dst, conn, actionStr, direction, origRule)
		}
	}
}

/*func (d *DFW) AddRule(src, dst []*endpoints.VM, conn *connection.Set, categoryStr string, actionStr string) {
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

	newRule := &fwRule{
		srcVMs: src,
		dstVMs: dst,
		conn:   connection.All(), // todo: change
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
		res.categoriesSpecs = append(res.categoriesSpecs, newEmptyCategory(c))
	}
	return res
}

func (d *DFW) GlobalDefaultAllow() bool {
	return d.defaultAction == actionAllow
}
