package dfw

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

type RuleAction string

const (
	ActionAllow     RuleAction = "allow"
	ActionDeny      RuleAction = "deny" // currently not differentiating between "reject" and "drop"
	ActionDrop      RuleAction = "drop"
	ActionJumpToApp RuleAction = "jump_to_application"
)

func (r RuleAction) String() string {
	return string(r)
}

func actionFromString(s string) RuleAction {
	switch strings.ToLower(s) {
	case string(ActionAllow):
		return ActionAllow
	case string(ActionDeny), "reject", "drop": // TODO: change
		return ActionDeny
	case string(ActionJumpToApp):
		return ActionJumpToApp
	default:
		panic("invalid input action")
	}
}

// FwRule captures original NSX dfw rule object with more relevant info for analysis/synthesis
type FwRule struct {
	Src                *RuleEndpoints
	Dst                *RuleEndpoints
	Scope              *RuleEndpoints // Scope implies additional condition on any Src and any Dst
	Conn               *netset.TransportSet
	Action             RuleAction
	direction          string //	"IN","OUT",	"IN_OUT"
	OrigRuleObj        *collector.Rule
	origDefaultRuleObj *collector.FirewallRule
	RuleID             int
	secPolicyName      string
	secPolicyCategory  string
	categoryRef        *CategorySpec
	dfwRef             *DFW
	Priority           int // the priority inside the category, (the index of the rule in category rules list)
}

// NewFwRule - create new FWRule object from input fields,
// expecting any such object to be created from this function
func NewFwRule(
	src *RuleEndpoints,
	dst *RuleEndpoints,
	scope *RuleEndpoints,
	conn *netset.TransportSet,
	action RuleAction,
	direction string,
	origRuleObj *collector.Rule,
	origDefaultRuleObj *collector.FirewallRule,
	ruleID int,
	secPolicyName string,
	secPolicyCategory string,
	categoryRef *CategorySpec,
	dfwRef *DFW,
	priority int,
) *FwRule {
	return &FwRule{
		Src:                src,
		Dst:                dst,
		Scope:              scope,
		Conn:               conn,
		Action:             action,
		direction:          direction,
		OrigRuleObj:        origRuleObj,
		origDefaultRuleObj: origDefaultRuleObj,
		RuleID:             ruleID,
		secPolicyName:      secPolicyName,
		secPolicyCategory:  secPolicyCategory,
		categoryRef:        categoryRef,
		dfwRef:             dfwRef,
		Priority:           priority,
	}
}

func (f *FwRule) RuleIDStr() string {
	return fmt.Sprintf("%d", f.RuleID)
}

func (f *FwRule) IsDenyAll() bool {
	return f.Action == ActionDeny &&
		f.Src.IsAllGroups &&
		f.Dst.IsAllGroups
}

func (f *FwRule) ruleDescriptionStr() string {
	return fmt.Sprintf("rule %d in category %s", f.RuleID, f.categoryRef.Category.String())
}

func (f *FwRule) ruleWarning(warnMsg string) {
	logging.Debugf("%s %s", f.ruleDescriptionStr(), warnMsg)
}

//////////////////////////////////////////////////////////////////////////////////////////
// computation of evaluated inbound and outbound rules
// 1. for analysis: inbound and outbound rules which effects the current topology
// 2. for synthesis: inbound and outbound rules which may not have effect on the current topology
//////////////////////////////////////////////////////////////////////////////////////////

func (f *FwRule) getEvaluatedRules(c *CategorySpec) (inbound, outbound *EvaluatedFWRule) {
	// for synthesis, we do not ignore rules with no VMs in src, dst, since in the future the same src
	// may have VMs in it. Empty connection, however, is empty regardless of the VMs snapshot
	if f.Conn.IsEmpty() {
		f.ruleWarning("has no effective inbound/outbound component, since its inferred services are empty")
		return nil, nil
	}

	inbound = f.getInboundRule()
	outbound = f.getOutboundRule()

	// check if rules are considered effective or not
	if len(f.Scope.VMs) == 0 {
		// rules with no VMs in src, dst are not considered effective rules
		f.ruleWarning("has no effective inbound/outbound component, since its scope component is empty")
		c.ineffectiveRules[f.RuleID] = append(c.ineffectiveRules[f.RuleID], "empty scope")
		// fields IsEffective remain false
		return inbound, outbound
	}

	isInboundEffective, isOutboundEffective := f.isRuleEffective(c)

	// update IsEffective field
	if isInboundEffective && inbound != nil {
		inbound.IsEffective = true
	}
	if isOutboundEffective && outbound != nil {
		outbound.IsEffective = true
	}

	return inbound, outbound
}

func (f *FwRule) getInboundRule() *EvaluatedFWRule {
	// if action is OUT -> return nil
	if !f.hasInboundComponent() {
		f.ruleWarning("has no effective inbound component, since its direction is OUT only")
		return nil
	}
	// inbound rule operates on intersection(dest, scope)
	// todo:
	// the result is a bad mix, because the src/dst ruleEndpoints considers intersection of vm compnent (per scope),
	//  but original groups without scope consideration
	// consider splitting to separate types, for capturing different pieces of info
	return f.inboundOrOutboundRule(nsx.RuleDirectionIN, topology.Intersection(f.Dst.VMs, f.Scope.VMs))
}

func (f *FwRule) getOutboundRule() *EvaluatedFWRule {
	// if action is IN -> return nil
	if !f.hasOutboundComponent() {
		f.ruleWarning("has no effective outbound component, since its direction is IN only")
		return nil
	}
	// outbound rule operates on intersection(src, scope)
	return f.inboundOrOutboundRule(nsx.RuleDirectionOUT, topology.Intersection(f.Src.VMs, f.Scope.VMs))
}

// common functionality used for evaluating inbound and outbound rules; effective and (potentially) non-effective

func (f *FwRule) hasInboundComponent() bool {
	// direction is either "in" or "in_out"
	return f.direction != string(nsx.RuleDirectionOUT)
}

func (f *FwRule) hasOutboundComponent() bool {
	// direction is either "out" or "in_out"
	return f.direction != string(nsx.RuleDirectionIN)
}

const (
	emptySrc = "empty src"
	emptyDst = "empty dest"
)

func (f *FwRule) isRuleEffective(c *CategorySpec) (inbound, outbound bool) {
	if len(f.Dst.VMs) == 0 && len(f.Dst.Blocks) == 0 {
		c.ineffectiveRules[f.RuleID] = append(c.ineffectiveRules[f.RuleID], emptyDst)
		f.ruleWarning("has no effective inbound/outbound component, since its dest-vms component is empty")
		return false, false
	}
	if len(f.Src.VMs) == 0 && len(f.Src.Blocks) == 0 {
		c.ineffectiveRules[f.RuleID] = append(c.ineffectiveRules[f.RuleID], emptySrc)
		f.ruleWarning("has no effective inbound/outbound component, since its src-vms component is empty")
		return false, false
	}
	inbound = true
	outbound = true
	// check inbound with scope
	newDest := topology.Intersection(f.Dst.VMs, f.Scope.VMs)
	if len(newDest) == 0 {
		c.ineffectiveRules[f.RuleID] = append(c.ineffectiveRules[f.RuleID], "empty dest with scope")
		f.ruleWarning("has no effective inbound component, since its intersection for dest & scope is empty")
		inbound = false
	}
	// check outbound with scope
	newSrc := topology.Intersection(f.Src.VMs, f.Scope.VMs)
	if len(newSrc) == 0 {
		c.ineffectiveRules[f.RuleID] = append(c.ineffectiveRules[f.RuleID], "empty src with scope")
		f.ruleWarning("has no effective outbound component, since its intersection for src & scope is empty")
		outbound = false
	}
	return inbound, outbound
}

func (f *FwRule) inboundOrOutboundRule(direction nsx.RuleDirection, capturedVMs []topology.Endpoint) *EvaluatedFWRule {
	return &EvaluatedFWRule{
		RuleObj:    f,
		Direction:  string(direction),
		OperatesOn: capturedVMs,
	}
}
