package dfw

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

type RuleAction string

const (
	listSeparatorStr = ","
	lineSeparatorStr = "\n"
)

/*var egressDirections = []string{"OUT", "IN_OUT"}
var ingressDirections = []string{"IN", "IN_OUT"}*/

const (
	actionAllow     RuleAction = "allow"
	actionDeny      RuleAction = "deny" // currently not differentiating between "reject" and "drop"
	actionJumpToApp RuleAction = "jump_to_application"
	actionNone      RuleAction = "none" // to mark that a default rule is not configured
)

/*func actionFromString(input string) RuleAction {
	switch input {
	case string(actionAllow):
		return actionAllow
	case string(actionDeny):
		return actionDeny
	case string(actionJumpToApp):
		return actionJumpToApp
	}
	return actionDeny
}*/

func actionFromString(s string) RuleAction {
	switch strings.ToLower(s) {
	case string(actionAllow):
		return actionAllow
	case string(actionDeny), "reject", "drop": // TODO: change
		return actionDeny
	case string(actionJumpToApp):
		return actionJumpToApp
	default:
		return actionNone
	}
}

type FwRule struct {
	srcVMs []*endpoints.VM
	dstVMs []*endpoints.VM
	scope  []*endpoints.VM
	// todo: the following 5 fields are needed for the symbolic expr in synthesis, and are temp until we handle the
	//       entire expr properly
	SrcGroups      []*collector.Group
	IsAllSrcGroups bool
	DstGroups      []*collector.Group
	IsAllDstGroups bool
	// Scope implies additional condition on any Src and any Dst; will be added in one of the last stages
	ScopeGroups        []*collector.Group
	conn               *netset.TransportSet
	Action             RuleAction
	direction          string //	"IN","OUT",	"IN_OUT"
	origRuleObj        *collector.Rule
	origDefaultRuleObj *collector.FirewallRule
	ruleID             int
	secPolicyName      string
	secPolicyCategory  string
	categoryRef        *CategorySpec
	dfwRef             *DFW
	// srcRuleObj ... todo: add a reference to the original rule retrieved from api

}

func (f *FwRule) effectiveRules() (inbound, outbound *FwRule) {
	if len(f.scope) == 0 {
		logging.Debugf("rule %d has no effective inbound/outbound component, since its scope component is empty", f.ruleID)
		return nil, nil
	}
	if f.conn.IsEmpty() {
		logging.Debugf("rule %d has no effective inbound/outbound component, since its traffic attributes are empty", f.ruleID)
		return nil, nil
	}
	return f.getInboundRule(), f.getOutboundRule()
}

func (f *FwRule) getInboundRule() *FwRule {
	// if action is OUT -> return nil
	if f.direction == string(nsx.RuleDirectionOUT) {
		logging.Debugf("rule %d has no effective inbound component, since its direction is OUT only", f.ruleID)
		return nil
	}
	if len(f.dstVMs) == 0 {
		logging.Debugf("rule %d has no effective inbound component, since its dest vms component is empty", f.ruleID)
		return nil
	}
	if len(f.srcVMs) == 0 {
		logging.Debugf("rule %d has no effective inbound component, since its target src vms component is empty", f.ruleID)
		return nil
	}

	// inbound rule operates on intersection(dest, scope)
	newDest := endpoints.Intersection(f.dstVMs, f.scope)
	if len(newDest) == 0 {
		logging.Debugf("rule %d has no effective inbound component, since its intersction for dest & scope is empty", f.ruleID)
		return nil
	}
	return &FwRule{
		srcVMs:         f.srcVMs,
		dstVMs:         newDest,
		SrcGroups:      f.SrcGroups,
		DstGroups:      f.DstGroups,
		IsAllSrcGroups: f.IsAllSrcGroups,
		IsAllDstGroups: f.IsAllDstGroups,
		ScopeGroups:    f.ScopeGroups,
		conn:           f.conn,
		Action:         f.Action,
		direction:      string(nsx.RuleDirectionIN),
		origRuleObj:    f.origRuleObj,
		ruleID:         f.ruleID,
		secPolicyName:  f.secPolicyName,
	}
}

func (f *FwRule) getOutboundRule() *FwRule {
	// if action is IN -> return nil
	if f.direction == string(nsx.RuleDirectionIN) {
		logging.Debugf("rule %d has no effective outbound component, since its direction is IN only", f.ruleID)
		return nil
	}
	if len(f.srcVMs) == 0 {
		logging.Debugf("rule %d has no effective outbound component, since its src vms component is empty", f.ruleID)
		return nil
	}

	if len(f.dstVMs) == 0 {
		logging.Debugf("rule %d has no effective outbound component, since its target dst vms component is empty", f.ruleID)
		return nil
	}

	// outbound rule operates on intersection(src, scope)
	newSrc := endpoints.Intersection(f.srcVMs, f.scope)
	if len(newSrc) == 0 {
		logging.Debugf("rule %d has no effective outbound component, since its intersction for src & scope is empty", f.ruleID)
		return nil
	}
	return &FwRule{
		srcVMs:         newSrc,
		dstVMs:         f.dstVMs,
		SrcGroups:      f.SrcGroups,
		DstGroups:      f.DstGroups,
		IsAllSrcGroups: f.IsAllSrcGroups,
		IsAllDstGroups: f.IsAllDstGroups,
		ScopeGroups:    f.ScopeGroups,
		conn:           f.conn,
		Action:         f.Action,
		direction:      string(nsx.RuleDirectionOUT),
		origRuleObj:    f.origRuleObj,
		ruleID:         f.ruleID,
		secPolicyName:  f.secPolicyName,
	}
}

func (f *FwRule) processedRuleCapturesPair(src, dst *endpoints.VM) bool {
	// in processed rule the src/dst vms already consider the original scope rule
	// and the separation to inound/outbound is done in advance
	return slices.Contains(f.srcVMs, src) && slices.Contains(f.dstVMs, dst)
}

// return whether the rule captures the input src,dst VMs on the given direction
/*func (f *FwRule) capturesPair(src, dst *endpoints.VM, isIngress bool) bool {
	vmsCaptured := slices.Contains(f.srcVMs, src) && slices.Contains(f.dstVMs, dst)
	if !vmsCaptured {
		return false
	}
	if isIngress {
		return slices.Contains(ingressDirections, f.direction) && slices.Contains(f.scope, dst)
	}
	return slices.Contains(egressDirections, f.direction) && slices.Contains(f.scope, src)
}*/

func vmsString(vms []*endpoints.VM) string {
	names := make([]string, len(vms))
	for i := range vms {
		names[i] = vms[i].Name()
	}
	return strings.Join(names, listSeparatorStr)
}

// return a string representation of a single rule
// groups are interpreted to VM members in this representation
func (f *FwRule) string() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s, scope: %s, sec-policy: %s",
		f.ruleID, vmsString(f.srcVMs), vmsString(f.dstVMs), f.conn.String(), string(f.Action), f.direction, vmsString(f.scope), f.secPolicyName)
}

func (f *FwRule) effectiveRuleStr() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s, sec-policy: %s",
		f.ruleID, vmsString(f.srcVMs), vmsString(f.dstVMs), f.conn.String(), string(f.Action), f.direction, f.secPolicyName)
}

func getDefaultRuleScope(r *collector.FirewallRule) string {
	res := []string{}
	for _, s := range r.AppliedTos {
		if s.TargetDisplayName != nil {
			res = append(res, *s.TargetDisplayName)
		}
	}
	return strings.Join(res, listSeparatorStr)
}

func (f *FwRule) getShortPathsString(paths []string) string {
	const (
		strLenLimit = 12
		pathSep     = "/"
		trimmedStr  = "..."
	)

	shortPaths := make([]string, len(paths))
	for i := range paths {
		// get display name from path when possible
		if name, ok := f.dfwRef.pathsToDisplayNames[paths[i]]; ok {
			shortPaths[i] = name
		} else {
			// shorten the path str in output
			pathElems := strings.Split(paths[i], pathSep)
			if len(pathElems) == 0 {
				continue
			}
			shortPaths[i] = pathElems[len(pathElems)-1]
		}
		if len(shortPaths[i]) > strLenLimit {
			// shorten long strings in output, to enable readable table of the input fw-rules
			shortPaths[i] = shortPaths[i][0:strLenLimit] + trimmedStr
		}
	}
	return strings.Join(shortPaths, listSeparatorStr)
}

func getRulesFormattedHeaderLine() string {
	var rulePropertiesHeaderList = []string{
		"ruleID",
		"ruleName",
		"src",
		"dst",
		"conn",
		"Action",
		"direction",
		"scope",
		"sec-policy",
		"Category",
	}
	return fmt.Sprintf("%s%s%s",
		common.Red,
		strings.Join(rulePropertiesHeaderList, "\t"),
		common.Reset)
}

// originalRuleStr returns a string representation of a single rule with original attribute values (including groups)
func (f *FwRule) originalRuleStr() string {
	const (
		anyStr = "ANY"
	)

	if f.origRuleObj == nil && f.origDefaultRuleObj == nil {
		logging.Debugf("warning: rule %d has no origRuleObj or origDefaultRuleObj", f.ruleID)
		return ""
	}

	// if this is a "default rule" from category with ConnectivityPreference configured,
	// the rule object is of different type
	if f.origRuleObj == nil && f.origDefaultRuleObj != nil {
		return fmt.Sprintf("%s%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s%s",
			common.Yellow,
			*f.origDefaultRuleObj.Id,
			*f.origDefaultRuleObj.DisplayName,
			// The default rule that gets created will be a any-any rule and applied
			// to entities specified in the scope of the security policy.
			anyStr,
			anyStr,
			anyStr,
			*f.origDefaultRuleObj.Action,
			f.origDefaultRuleObj.Direction,
			getDefaultRuleScope(f.origDefaultRuleObj),
			f.secPolicyName,
			f.secPolicyCategory,
			common.Reset,
		)
	}

	name := ""
	if f.origRuleObj.DisplayName != nil {
		name = *f.origRuleObj.DisplayName
	}
	return fmt.Sprintf("%s%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s%s",
		common.Yellow,
		f.ruleID,
		name,
		f.getShortPathsString(f.origRuleObj.SourceGroups),
		f.getShortPathsString(f.origRuleObj.DestinationGroups),
		// todo: origRuleObj.Services is not always the services, can also be service_entries
		f.getShortPathsString(f.origRuleObj.Services),
		string(f.Action), f.direction,
		strings.Join(f.origRuleObj.Scope, listSeparatorStr),
		f.secPolicyName,
		f.secPolicyCategory,
		common.Reset,
	)
}

// ComputeSymbolic computes symbolicSrc and symbolicDst
func (f *FwRule) ComputeSymbolic() {

}
