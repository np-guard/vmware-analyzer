package dfw

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
)

type DFW struct {
	CategoriesSpecs            []*CategorySpec // ordered list of categories
	TotalEffectiveIngressRules int
	TotalEffectiveEgressRules  int

	pathsToDisplayNames map[string]string // map from printing paths references as display names instead
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
func (d *DFW) String() string {
	return common.JoinStringifiedSlice(d.CategoriesSpecs, common.NewLine)
}

func (d *DFW) AllEffectiveRules() string {
	inboundResStr := common.JoinCustomStrFuncSlice(d.CategoriesSpecs,
		func(c *CategorySpec) string { return c.inboundEffectiveRulesStr() },
		common.NewLine)
	outboundResStr := common.JoinCustomStrFuncSlice(d.CategoriesSpecs,
		func(c *CategorySpec) string { return c.outboundEffectiveRulesStr() },
		common.NewLine)

	inbound := fmt.Sprintf("\nInbound effective rules only:%s%s\n", common.ShortSep, inboundResStr)
	outbound := fmt.Sprintf("\nOutbound effective rules only:%s%s", common.ShortSep, outboundResStr)
	return inbound + outbound
}

func (d *DFW) AddRule(src, dst, scope *RuleEndpoints, conn *netset.TransportSet, categoryStr, actionStr, direction string,
	ruleID int, origRule *collector.Rule, secPolicyName string,
	origDefaultRule *collector.FirewallRule) {
	for _, fwCategory := range d.CategoriesSpecs {
		if fwCategory.Category.String() == categoryStr {
			fwCategory.addRule(src, dst, scope, conn, actionStr, direction, ruleID, origRule, secPolicyName, origDefaultRule)
		}
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
