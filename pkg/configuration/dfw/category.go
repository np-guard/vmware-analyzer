package dfw

import (
	"slices"

	"github.com/np-guard/models/pkg/interval"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// https://dp-downloads.broadcom.com/api-content/apis/API_NTDCRA_001/4.2/html/api_includes/types_SecurityPolicy.html

// CategorySpec captures dfw cateogry policies configuration, with all rules by order
type CategorySpec struct {
	Category         collector.DfwCategory
	rules            []*FwRule  // ordered list of original rules (direction is in/out/in_out)
	EvaluatedRules   *EvalRules // ordered list of all evaluated inbound and outbound rules
	dfwRef           *DFW
	rulesMap         map[int]*FwRule  // map from ruleID to (orig) FwRule object (direction is in/out/in_out)
	ineffectiveRules map[int][]string // map from ruleID to string explaining reason for ineffective rule detected
}

func newEmptyCategory(c collector.DfwCategory, d *DFW) *CategorySpec {
	return &CategorySpec{
		Category:         c,
		dfwRef:           d,
		EvaluatedRules:   &EvalRules{},
		rulesMap:         map[int]*FwRule{},
		ineffectiveRules: map[int][]string{},
	}
}

func (c *CategorySpec) GetInboundEffectiveRules() []*EvaluatedFWRule {
	return common.NewFilteredSliceFunc(c.EvaluatedRules.InboundRules, func(r *EvaluatedFWRule) bool { return r.IsEffective })
}
func (c *CategorySpec) GetOutboundEffectiveRules() []*EvaluatedFWRule {
	return common.NewFilteredSliceFunc(c.EvaluatedRules.OutboundRules, func(r *EvaluatedFWRule) bool { return r.IsEffective })
}

// addRule adds a FWRule from input fields to list of category's original rules + adds relevant inbound/outbound evaluated rules
// for the list of evaluated rules (and effective rules if the input rule is considered effective)
func (c *CategorySpec) addRule(src, dst, scope *RuleEndpoints, conn *netset.TransportSet, action, direction string, ruleID int,
	origRule *collector.Rule, secPolicyName string, origDefaultRule *collector.FirewallRule) {
	// create FWRule object from input field values
	newRule := NewFwRule(src, dst, scope, conn, actionFromString(action), direction, origRule, origDefaultRule, ruleID,
		secPolicyName, c.Category.String(), c, c.dfwRef, len(c.rules))

	// add FWRule object to list of original rules
	c.rules = append(c.rules, newRule)
	c.rulesMap[newRule.RuleID] = newRule

	if c.Category == collector.EthernetCategory {
		logging.Debugf(
			"Ethernet category not supported - rule %d in Ethernet category is ignored and not added to list of effective/evaluated rules", ruleID)
		return
	}

	// get evaluated inbound/outbound rules from the original newRule + effective rules
	inbound, outbound := newRule.getEvaluatedRules(c)

	c.EvaluatedRules.addInboundOrOutboundRule(true, inbound, c.dfwRef)
	c.EvaluatedRules.addInboundOrOutboundRule(false, outbound, c.dfwRef)
}

type EvaluatedFWRule struct {
	// the original rule object
	RuleObj *FwRule

	// Direction is either "in" or "out" for an evaluated rule
	Direction string

	// OperatesOn is the list of VMs on which this rules operates on - considering scope;
	// if the rule is inbound, these are the dest vms (after intersction with scope),
	// and if the rule is outbound, these are the src vms (after intersction with scope),
	OperatesOn []topology.Endpoint

	// IsEffective indicates if this rule is considered infeffective for analysis
	IsEffective bool
}

func (e *EvaluatedFWRule) CapturesPair(src, dst topology.Endpoint) bool {
	if e.Direction == string(nsx.RuleDirectionIN) {
		return e.RuleObj.Src.ContainsEndpoint(src) && slices.Contains(e.OperatesOn, dst)
	}
	return e.RuleObj.Dst.ContainsEndpoint(dst) && slices.Contains(e.OperatesOn, src)
}

// EvalRules are built from original rules, split to separate Inbound & Outbound rules,
// they consider already the scope from the original rules
type EvalRules struct {
	InboundRules  []*EvaluatedFWRule
	OutboundRules []*EvaluatedFWRule
}

func (e *EvalRules) addInboundOrOutboundRule(isInbound bool, r *EvaluatedFWRule, d *DFW) {
	var rules *[]*EvaluatedFWRule
	var effectiveCounter *int
	if isInbound {
		rules = &e.InboundRules
		effectiveCounter = &d.TotalEffectiveIngressRules
	} else {
		rules = &e.OutboundRules
		effectiveCounter = &d.TotalEffectiveEgressRules
	}

	if r != nil {
		*rules = append(*rules, r)
		if r.IsEffective {
			*effectiveCounter += 1
		}
	}
}

const detailedRuleSeparator = "\n---\n"

func (c *CategorySpec) evaluatedRulesStr(isInbound bool) string {
	var rules []*EvaluatedFWRule
	if isInbound {
		rules = c.EvaluatedRules.InboundRules
	} else {
		rules = c.EvaluatedRules.OutboundRules
	}
	return common.JoinCustomStrFuncSlice(rules,
		func(f *EvaluatedFWRule) string { return f.evaluatedRuleStr() },
		detailedRuleSeparator)
}

func (c *CategorySpec) originalRulesComponentsStr() [][]string {
	rulesStr := make([][]string, len(c.rules))
	for i := range c.rules {
		rulesStr[i] = c.rules[i].originalRuleComponentsStr()
	}
	return rulesStr
}

// return a map from potential redundant rule ID, to the list of rule IDs that are "covering" this rule
//
//nolint:gocritic //keep comments for now
func (c *CategorySpec) potentialRedundantRules(rulesPerDirection []*EvaluatedFWRule, allVMs []topology.Endpoint) map[int][]int {
	res := map[int][]int{}
	// logging.Debugf("called potentialRedundantRules for catrgory %s", c.Category.String())
	vmNameToIndex := map[string]int{}
	// index `i` to VM is just allVMs[i]
	for i, vm := range allVMs {
		vmNameToIndex[vm.String()] = i
	}

	// iterate inbound and outbound effective rules separately
	for i, ruleI := range rulesPerDirection {
		// todo: should consider src/dst with scope from evaluated rule instead
		srcObj := ruleI.RuleObj.Src
		dstObj := ruleI.RuleObj.Dst
		conn := ruleI.RuleObj.Conn
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
		ruleIHC := netset.NewDiscreteEndpointsTrafficSet(vmsToIntervalSet(srcObj.VMs), vmsToIntervalSet(dstObj.VMs), conn)

		priorRulesHC := netset.EmptyDiscreteEndpointsTrafficSet()

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
			ruleJHC := netset.NewDiscreteEndpointsTrafficSet(
				vmsToIntervalSet(ruleJ.RuleObj.Src.VMs),
				vmsToIntervalSet(ruleJ.RuleObj.Dst.VMs),
				ruleJ.RuleObj.Conn)
			if !ruleIHC.Intersect(ruleJHC).IsEmpty() {
				coveringRules = append(coveringRules, ruleJ.RuleObj.RuleID)
			}

			priorRulesHC = priorRulesHC.Union(ruleJHC)
		}
		// after iterating all prior rules - check if they already cover all ruleI tuples
		delta := ruleIHC.Subtract(priorRulesHC)
		if delta.IsEmpty() {
			// logging.Debugf("rule %d (inbound )is potentially redundant, covered by rules: %v", ruleI.RuleID, coveringRules)
			res[ruleI.RuleObj.RuleID] = coveringRules
		}
	}
	return res
}

func (c *CategorySpec) SearchDefaultDenyRule() *FwRule {
	for _, rule := range c.rules {
		if rule.IsDenyAll() {
			return rule
		}
	}
	return nil
}
