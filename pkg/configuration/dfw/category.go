package dfw

import (
	"fmt"

	"github.com/np-guard/models/pkg/interval"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// https://dp-downloads.broadcom.com/api-content/apis/API_NTDCRA_001/4.2/html/api_includes/types_SecurityPolicy.html

// CategorySpec captures dfw cateogry policies configuration, with all rules by order
type CategorySpec struct {
	Category       collector.DfwCategory
	Rules          []*FwRule  // ordered list of original rules (direction is in/out/in_out)
	EvaluatedRules *EvalRules // ordered list of all evaluated inbound and outbound rules
	EffectiveRules *EvalRules // ordered list of only effective inbound and outbound rules
	dfwRef         *DFW
	rulesMap       map[int]*FwRule // map from ruleID to (orig) FwRule object (direction is in/out/in_out)
}

func newEmptyCategory(c collector.DfwCategory, d *DFW) *CategorySpec {
	return &CategorySpec{
		Category:       c,
		dfwRef:         d,
		EvaluatedRules: &EvalRules{},
		EffectiveRules: &EvalRules{},
		rulesMap:       map[int]*FwRule{},
	}
}

// addRule adds a FWRule from input fields to list of category's original rules + adds relevant inbound/outbound evaluated rules
// for the list of evaluated rules (and effective rules if the input rule is considered effective)
func (c *CategorySpec) addRule(src, dst, scope *RuleEndpoints, conn *netset.TransportSet, action, direction string, ruleID int,
	origRule *collector.Rule, secPolicyName string, origDefaultRule *collector.FirewallRule) {
	// create FWRule object from input field values
	newRule := NewFwRule(src, dst, scope, conn, actionFromString(action), direction, origRule, origDefaultRule, ruleID,
		secPolicyName, c.Category.String(), c, c.dfwRef, len(c.Rules))

	// add FWRule object to list of original rules
	c.Rules = append(c.Rules, newRule)
	c.rulesMap[newRule.RuleID] = newRule

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
			d.TotalEffectiveIngressRules += 1
		}
	}
}

func (e *EvalRules) addOutboundRule(r *FwRule, d *DFW, isEffective bool) {
	if r != nil {
		e.Outbound = append(e.Outbound, r)
		if isEffective {
			d.TotalEffectiveEgressRules += 1
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

// return a map from potential redundant rule ID, to the list of rule IDs that are "covering" this rule
//
//nolint:gocritic //keep comments for now
func (c *CategorySpec) potentialRedundantRules(rulesPerDirection []*FwRule, allVMs []topology.Endpoint) map[int][]int {
	res := map[int][]int{}
	// logging.Debugf("called potentialRedundantRules for catrgory %s", c.Category.String())
	vmNameToIndex := map[string]int{}
	// index `i` to VM is just allVMs[i]
	for i, vm := range allVMs {
		vmNameToIndex[vm.String()] = i
	}

	// iterate inbound and outbound effective rules separately
	for i, ruleI := range rulesPerDirection {
		srcObj := ruleI.Src
		dstObj := ruleI.Dst
		conn := ruleI.Conn
		coveringRules := []int{}

		vmsToIntervalSet := func(vms []topology.Endpoint) *interval.CanonicalSet {
			res := interval.NewCanonicalSet()
			for _, vm := range vms {
				index := int64(vmNameToIndex[vm.Name()])
				res.AddInterval(interval.New(index, index))
			}
			return res
		}

		// hc of ruleI
		ruleIHC := common.NewDiscreteEndpointsTrafficSet(vmsToIntervalSet(srcObj.VMs), vmsToIntervalSet(dstObj.VMs), conn)

		priorRulesHC := common.EmptyDiscreteEndpointsTrafficSet()

		// todo: consider opposite direction for iteration, and consider stop as soon as full coverage is detected
		/*for j := i - 1; j >= 0; j-- {
			ruleJ := rulesPerDirection[j]
			ruleJHC := netset.NewSimpleEndpointsTrafficSet(vmsToIntervalSet(ruleJ.Src.VMs), vmsToIntervalSet(ruleJ.Dst.VMs), ruleJ.Conn)
			if ruleJHC.IsSubset(priorRulesHC) {
				continue
			}
		}*/

		// vm-based redundancy computation
		// todo: consider expression-based computation

		for j := range i { // iterate higher-prio rules
			// look for tuples of (src, dst, conn) already covering rule[i] - action does not matter [match is based on this tupple]
			ruleJ := rulesPerDirection[j]
			ruleJHC := common.NewDiscreteEndpointsTrafficSet(vmsToIntervalSet(ruleJ.Src.VMs), vmsToIntervalSet(ruleJ.Dst.VMs), ruleJ.Conn)
			if !ruleIHC.Intersect(ruleJHC).IsEmpty() {
				coveringRules = append(coveringRules, ruleJ.RuleID)
			}

			priorRulesHC = priorRulesHC.Union(ruleJHC)
		}
		// after iterating all prior rules - check if they already cover all ruleI tuples
		delta := ruleIHC.Subtract(priorRulesHC)
		if delta.IsEmpty() {
			// logging.Debugf("rule %d (inbound )is potentially redundant, covered by rules: %v", ruleI.RuleID, coveringRules)
			res[ruleI.RuleID] = coveringRules
		}
	}
	return res
}
