package dfw

import (
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type DFW struct {
	categoriesSpecs []*categorySpec // ordered list of categories
	defaultAction   ruleAction      // global default (?)
}

// for a pair of src,dst vms, return the set of allowed connections
func (d *DFW) AnalyzeDFW(src, dst *endpoints.VM) (allowedConns *connection.Set) {
	// accumulate the following sets, from all categories - by order
	allAllowedConns := connection.None()
	allDeniedConns := connection.None()
	allNotDeterminedConns := connection.None()

	for _, dfwCategory := range d.categoriesSpecs {
		if dfwCategory.category == ethernetCategory {
			continue // cuurently skip L2 rules
		}
		// get analyzed conns from this category
		categoryAllowedConns, categoryJumptToAppConns, categoryDeniedConns, categoryNotDeterminedConns := dfwCategory.analyzeCategory(src, dst)

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
func (d *DFW) AddRule(src, dst *endpoints.VM, conn *connection.Set, category string, action string) {
	for _, fwCategory := range d.categoriesSpecs {
		if fwCategory.category.string() == category {
			fwCategory.addRule(src, dst, conn, action)
		}
	}
}

// NewEmptyDFW func for testing purposes
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
