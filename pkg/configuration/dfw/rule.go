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

/*var egressDirections = []string{"OUT", "IN_OUT"}
var ingressDirections = []string{"IN", "IN_OUT"}*/

const (
	ActionAllow     RuleAction = "allow"
	ActionDeny      RuleAction = "deny" // currently not differentiating between "reject" and "drop"
	ActionJumpToApp RuleAction = "jump_to_application"
)

/*func actionFromString(input string) RuleAction {
	switch input {
	case string(ActionAllow):
		return ActionAllow
	case string(ActionDeny):
		return ActionDeny
	case string(ActionJumpToApp):
		return ActionJumpToApp
	}
	return ActionDeny
}*/

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

type RuleEndPoints struct {
	VMs         []topology.Endpoint
	Groups      []*collector.Group
	IsAllGroups bool
	Blocks      []*topology.RuleIPBlock
}

// FwRule captures original NSX dfw rule object with more relevant info for analysis/synthesis
type FwRule struct {
	Src   RuleEndPoints
	Dst   RuleEndPoints
	Scope RuleEndPoints

	// Scope implies additional condition on any Src and any Dst
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
	src *RuleEndPoints,
	dst *RuleEndPoints,
	scope *RuleEndPoints,
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
		Src:                *src,
		Dst:                *dst,
		Scope:              *scope,
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

func (f *FwRule) getEvaluatedRulesAndEffectiveRules() (inbound, outbound, inboundEffective, outboundEffective *FwRule) {
	// for synthesis, we do not ignore rules with no VMs in src, dst, since in the future the same src
	// may have VMs in it. Empty connection, however, is empty regardless of the VMs snapshot
	if f.Conn.IsEmpty() {
		f.ruleWarning("has no effective inbound/outbound component, since its inferred services are empty")
		return nil, nil, nil, nil
	}

	inbound = f.getInboundRule()
	outbound = f.getOutboundRule()

	// check if rules are considered effective or not
	if len(f.Scope.VMs) == 0 {
		// rules with no VMs in src, dst are not considered effective rules
		f.ruleWarning("has no effective inbound/outbound component, since its scope component is empty")
		return inbound, outbound, nil, nil
	}

	if inboundNotEffectiveMsg := f.checkInboundEffectiveRuleValidity(); inboundNotEffectiveMsg != "" {
		f.ruleWarning(inboundNotEffectiveMsg)
	} else if inbound != nil {
		inboundEffective = inbound.clone()
	}

	if outboundNotEffectiveMsg := f.checkOutboundEffectiveRuleValidity(); outboundNotEffectiveMsg != "" {
		f.ruleWarning(outboundNotEffectiveMsg)
		outboundEffective = nil
	} else if outbound != nil {
		outboundEffective = outbound.clone()
	}

	return inbound, outbound, inboundEffective, outboundEffective
}

func (f *FwRule) getInboundRule() *FwRule {
	// if action is OUT -> return nil
	if !f.hasInboundComponent() {
		f.ruleWarning("has no effective inbound component, since its direction is OUT only")
		return nil
	}
	// inbound rule operates on intersection(dest, scope)
	return f.inboundOrOutboundRule(nsx.RuleDirectionIN, f.Src.VMs, topology.Intersection(f.Dst.VMs, f.Scope.VMs))
}

func (f *FwRule) getOutboundRule() *FwRule {
	// if action is IN -> return nil
	if !f.hasOutboundComponent() {
		f.ruleWarning("has no effective outbound component, since its direction is IN only")
		return nil
	}
	// outbound rule operates on intersection(src, scope)
	return f.inboundOrOutboundRule(nsx.RuleDirectionOUT, topology.Intersection(f.Src.VMs, f.Scope.VMs), f.Dst.VMs)
}

// common functionality used for evaluating inbound and outbound rules; effective and (potentially) non-effective

func (f *FwRule) hasInboundComponent() bool {
	return f.direction != string(nsx.RuleDirectionOUT)
}

func (f *FwRule) hasOutboundComponent() bool {
	return f.direction != string(nsx.RuleDirectionIN)
}

// checks validity of inbound component of FwRule f; if valid returns the empty string, otherwise returns ruleWarning string
func (f *FwRule) checkInboundEffectiveRuleValidity() string {
	if len(f.Dst.VMs) == 0 {
		return "has no effective inbound component, since its dest-vms component is empty"
	}
	if len(f.Src.VMs) == 0 {
		return "has no effective inbound component, since its target src-vms component is empty"
	}
	newDest := topology.Intersection(f.Dst.VMs, f.Scope.VMs)
	if len(newDest) == 0 {
		return "has no effective inbound component, since its intersection for dest & scope is empty"
	}
	return ""
}

// checks validity of inbound component of FwRule f; if valid returns the empty string, otherwise returns ruleWarning string
func (f *FwRule) checkOutboundEffectiveRuleValidity() string {
	if len(f.Src.VMs) == 0 {
		return "has no effective outbound component, since its src vms component is empty"
	}
	if len(f.Dst.VMs) == 0 {
		return "has no effective outbound component, since its target dst vms component is empty"
	}
	// outbound rule operates on intersection(src, scope)
	newSrc := topology.Intersection(f.Src.VMs, f.Scope.VMs)
	if len(newSrc) == 0 {
		return "has no effective outbound component, since its intersection for src & scope is empty"
	}
	return ""
}

func (f *FwRule) clone() *FwRule {
	return NewFwRule(&f.Src, &f.Dst, &f.Scope, f.Conn, f.Action,
		f.direction, f.OrigRuleObj, f.origDefaultRuleObj, f.RuleID, f.secPolicyName,
		f.secPolicyCategory, f.categoryRef, f.dfwRef, f.Priority)
}

func (f *FwRule) inboundOrOutboundRule(direction nsx.RuleDirection, src, dest []topology.Endpoint) *FwRule {
	// duplicating most fields, only updating src,dst as evaluated with scope + updating to one direction option (in/out),
	// and scope field is changed to nil
	res := f.clone()
	res.Src.VMs = src
	res.Dst.VMs = dest
	res.Scope = f.Scope
	res.direction = string(direction)

	return res
}

// return whether the rule captures the input src,dst VMs on the given direction
/*func (f *FwRule) capturesPair(src, dst topology.EP, isIngress bool) bool {
	vmsCaptured := slices.Contains(f.Src.VMs, src) && slices.Contains(f.Dst.VMs, dst)
	if !vmsCaptured {
		return false
	}
	if isIngress {
		return slices.Contains(ingressDirections, f.direction) && slices.Contains(f.scope, dst)
	}
	return slices.Contains(egressDirections, f.direction) && slices.Contains(f.scope, src)
}*/
