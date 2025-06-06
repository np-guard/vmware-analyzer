package dfw

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

type DFW struct {
	CategoriesSpecs            []*CategorySpec // ordered list of categories
	TotalEffectiveIngressRules int
	TotalEffectiveEgressRules  int

	pathsToDisplayNames map[string]string // map from printing paths references as display names instead
	AllRulesIDs         []int
}

func (d *DFW) OriginalRulesStrFormatted(color bool) string {
	header := getRulesHeader()
	lines := [][]string{}
	for _, c := range d.CategoriesSpecs {
		lines = append(lines, c.originalRulesComponentsStr()...)
	}
	return "original rules:\n" + common.GenerateTableString(header, lines, &common.TableOptions{Colors: color})
}

// return a string rep that shows the fw-rules in all categories
/*func (d *DFW) AllEvaluatedRulesDetails() string {
	return common.JoinStringifiedSlice(d.CategoriesSpecs, common.NewLine)
}*/

func (d *DFW) AllEvaluatedRulesDetails() string {
	inboundResStr := common.JoinCustomStrFuncSlice(d.CategoriesSpecs,
		func(c *CategorySpec) string { return c.evaluatedRulesStr(true) },
		common.NewLine)
	outboundResStr := common.JoinCustomStrFuncSlice(d.CategoriesSpecs,
		func(c *CategorySpec) string { return c.evaluatedRulesStr(false) },
		common.NewLine)

	inbound := fmt.Sprintf("\nInbound evaluated rules only:%s%s\n", common.ShortSep, inboundResStr)
	outbound := fmt.Sprintf("\nOutbound evaluated rules only:%s%s\n%s\n", common.ShortSep, outboundResStr, common.ShortSep)
	return inbound + outbound
}

func (d *DFW) AddRule(src, dst, scope *RuleEndpoints, conn *netset.TransportSet, categoryStr, actionStr, direction string,
	ruleID int, origRule *collector.Rule, secPolicyName string,
	origDefaultRule *collector.FirewallRule) {
	added := false
	for _, fwCategory := range d.CategoriesSpecs {
		if fwCategory.Category.String() == categoryStr {
			fwCategory.addRule(src, dst, scope, conn, actionStr, direction, ruleID, origRule, secPolicyName, origDefaultRule)
			added = true
			d.AllRulesIDs = append(d.AllRulesIDs, ruleID)
		}
	}
	if !added {
		logging.Warnf("rule id %d from category %s was not added to any exitsing category in DFW model", ruleID, categoryStr)
	}
}

// NewEmptyDFW returns new DFW with global default as from input
func NewEmptyDFW() *DFW {
	res := &DFW{}
	for _, c := range collector.CategoriesList {
		res.CategoriesSpecs = append(res.CategoriesSpecs, newEmptyCategory(c, res))
	}
	return res
}

func (d *DFW) SetPathsToDisplayNames(m map[string]string) {
	d.pathsToDisplayNames = m
}

// look for rules shadowed by higher-prio rules (single rule or combination of some rules)
func (d *DFW) redundantRulesAnalysisPerCategory(allVMs []topology.Endpoint, categoryIndex int) (reportLines [][]string) {
	category := d.CategoriesSpecs[categoryIndex]
	inboundRedundant := category.potentialRedundantRules(category.GetInboundEffectiveRules(), allVMs)
	outboundRedundant := category.potentialRedundantRules(category.GetOutboundEffectiveRules(), allVMs)

	for rID, ruleObj := range category.rulesMap {
		inCovering, okIn := inboundRedundant[rID]
		outCovering, okOut := outboundRedundant[rID]
		if !okIn && !okOut {
			continue
		}

		switch ruleObj.direction {
		case string(nsx.RuleDirectionOUT):
			if okOut {
				logging.Debug2f("rule %d (outbound) is potentially redundant, covered by rules: %v", rID, outCovering)
				reportLines = append(reportLines, []string{fmt.Sprintf("%d", rID), category.Category.String(),
					string(nsx.RuleDirectionOUT), fmt.Sprintf("%v", outCovering)})
			}
		case string(nsx.RuleDirectionIN):
			if okIn {
				logging.Debug2f("rule %d (inbound) is potentially redundant, covered by rules: %v", rID, inCovering)
				reportLines = append(reportLines, []string{fmt.Sprintf("%d", rID), category.Category.String(),
					string(nsx.RuleDirectionIN), fmt.Sprintf("%v", inCovering)})
			}

		case string(nsx.RuleDirectionINOUT):
			if okIn && okOut {
				unionRules := slices.Concat(inCovering, outCovering)
				sort.IntSlice(unionRules).Sort()
				unionRules = slices.Compact(unionRules)
				logging.Debug2f("rule %d (in_out) is potentially redundant, covered by rules: %v", rID, unionRules)
				reportLines = append(reportLines, []string{fmt.Sprintf("%d", rID), category.Category.String(),
					string(nsx.RuleDirectionINOUT), fmt.Sprintf("%v", unionRules)})
			}
		}
	}

	return reportLines
}

// RedundantRulesAnalysis returns as string a report of possible DFW redundant rules (category-scoped), VMs-based analysis;
// if all src,dst VMs of a rule R, with R's services, are covered (determined) in higher-priority rules, then we consider R
// as potentially redundant.
// also returns report lines (for testing purposes)
func (d *DFW) RedundantRulesAnalysis(allVMs []topology.Endpoint, color bool) (report string, reportLines [][]string) {
	// this report includes shadowed rules

	var reportHeader = []string{"Potential shadowed DFW rule ID", "DFW Category", "Direction", "Shadowing rules IDs"}
	reportLines = [][]string{}
	for i := range len(d.CategoriesSpecs) {
		categoryRedundantRules := d.redundantRulesAnalysisPerCategory(allVMs, i)
		reportLines = append(reportLines, categoryRedundantRules...)
	}

	if len(reportLines) == 0 {
		return "", reportLines
	}
	return common.GenerateTableString(reportHeader, reportLines, &common.TableOptions{SortLines: true, Colors: color}), reportLines
}

func (d *DFW) IneffectiveRulesReport(color bool) string {
	// this report includes ineffective rules due to empty src/dst/scope...
	var reportHeader = []string{"Ineffective DFW rule ID", "Description"}
	var reportLines = [][]string{}
	for i := range len(d.CategoriesSpecs) {
		category := d.CategoriesSpecs[i]
		for rID, description := range category.ineffectiveRules {
			slices.Sort(description)
			line := []string{fmt.Sprintf("%d", rID), strings.Join(slices.Compact(description), common.CommaSpaceSeparator)}
			reportLines = append(reportLines, line)
		}
	}
	if len(reportLines) == 0 {
		return ""
	}
	return common.GenerateTableString(reportHeader, reportLines, &common.TableOptions{SortLines: true, Colors: color})
}
