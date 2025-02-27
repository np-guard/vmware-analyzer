package dfw

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"

	"github.com/np-guard/vmware-analyzer/pkg/configuration/endpoints"
)

// https://dp-downloads.broadcom.com/api-content/apis/API_NTDCRA_001/4.2/html/api_includes/types_SecurityPolicy.html

// CategorySpec captures dfw cateogry policies configuration, with all rules by order
type CategorySpec struct {
	Category       collector.DfwCategory
	Rules          []*FwRule  // ordered list of original rules (direction is in/out/in_out)
	EvaluatedRules *EvalRules // ordered list of all evaluated inbound and outbound rules
	EffectiveRules *EvalRules // ordered list of only effective inbound and outbound rules
	dfwRef         *DFW
}

func newEmptyCategory(c collector.DfwCategory, d *DFW) *CategorySpec {
	return &CategorySpec{
		Category:       c,
		dfwRef:         d,
		EvaluatedRules: &EvalRules{},
		EffectiveRules: &EvalRules{},
	}
}

// addRule adds a FWRule from input fields to list of category's original rules + adds relevant inbound/outbound evaluated rules
// for the list of evaluated rules (and effective rules if the input rule is considered effective)
func (c *CategorySpec) addRule(src, dst []endpoints.EP, srcBlocks, dstBlocks []*endpoints.RuleIPBlock,
	srcGroups, dstGroups, scopeGroups []*collector.Group,
	isAllSrcGroup, isAllDstGroup bool, conn *netset.TransportSet, action, direction string, ruleID int,
	origRule *collector.Rule, scope []endpoints.EP, secPolicyName string,
	origDefaultRule *collector.FirewallRule) {
	// create FWRule object from input field values
	newRule := NewFwRule(src, dst, srcBlocks, dstBlocks, scope, srcGroups, isAllSrcGroup, dstGroups, isAllDstGroup, scopeGroups, conn,
		actionFromString(action), direction, origRule, origDefaultRule, ruleID, secPolicyName, c.Category.String(), c, c.dfwRef, len(c.Rules))

	// add FWRule object to list of original rules
	c.Rules = append(c.Rules, newRule)

	if c.Category == collector.EthernetCategory {
		logging.Debugf(
			"Ethernet category not supported - rule %d in Ethernet category is ignored and not added to list of effective/evaluated rules", ruleID)
		return
	}

	// get evaluated inbound/outbound rules from the original newRule + effective rules
	inbound, outbound, inboundEffective, outboundEffective := newRule.getEvaluatedRulesAndEffectiveRules()

	c.EvaluatedRules.addInboundRule(inbound, c.dfwRef, false)
	c.EvaluatedRules.addOutboundRule(outbound, c.dfwRef, false)

	c.EffectiveRules.addInboundRule(inboundEffective, c.dfwRef, true)
	c.EffectiveRules.addOutboundRule(outboundEffective, c.dfwRef, true)
}

// EvalRules are built from original rules, split to separate Inbound & Outbound rules,
// they consider already the scope from the original rules
type EvalRules struct {
	Inbound  []*FwRule
	Outbound []*FwRule
}

func (e *EvalRules) addInboundRule(r *FwRule, d *DFW, isEffective bool) {
	if r != nil {
		e.Inbound = append(e.Inbound, r)
		if isEffective {
			d.totalEffectiveIngressRules += 1
		}
	}
}

func (e *EvalRules) addOutboundRule(r *FwRule, d *DFW, isEffective bool) {
	if r != nil {
		e.Outbound = append(e.Outbound, r)
		if isEffective {
			d.totalEffectiveEgressRules += 1
		}
	}
}

func (c *CategorySpec) inboundEffectiveRulesStr() string {
	return common.JoinCustomStrFuncSlice(c.EffectiveRules.Inbound,
		func(f *FwRule) string { return f.effectiveRuleStr() },
		common.NewLine)
}

func (c *CategorySpec) outboundEffectiveRulesStr() string {
	return common.JoinCustomStrFuncSlice(c.EffectiveRules.Outbound,
		func(f *FwRule) string { return f.effectiveRuleStr() },
		common.NewLine)
}

func (c *CategorySpec) originalRulesComponentsStr() [][]string {
	rulesStr := make([][]string, len(c.Rules))
	for i := range c.Rules {
		rulesStr[i] = c.Rules[i].originalRuleComponentsStr()
	}
	return rulesStr
}
func (c *CategorySpec) String() string {
	rulesStr := common.JoinStringifiedSlice(c.Rules, common.NewLine)
	return fmt.Sprintf("category: %s\nrules:\n%s\n", c.Category.String(), rulesStr)
}
