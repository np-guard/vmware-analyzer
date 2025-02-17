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
	Conn               *netset.TransportSet
	Action             RuleAction
	Direction          string //	"IN","OUT",	"IN_OUT"
	OrigRuleObj        *collector.Rule
	origDefaultRuleObj *collector.FirewallRule
	RuleID             int
	secPolicyName      string
	secPolicyCategory  string
	categoryRef        *CategorySpec
	dfwRef             *DFW
	Priority           int
	// srcRuleObj ... todo: add a reference to the original rule retrieved from api

}

func (f *FwRule) RuleIDStr() string {
	return fmt.Sprintf("%d", f.RuleID)
}

func (f *FwRule) IsDenyAll() bool {
	return f.Action == ActionDeny &&
		f.IsAllSrcGroups &&
		f.IsAllDstGroups
}

func (f *FwRule) ruleDescriptionStr() string {
	return fmt.Sprintf("rule %d in category %s", f.RuleID, f.categoryRef.Category.String())
}

func (f *FwRule) ruleWarning(warnMsg string) {
	logging.Debugf("%s %s", f.ruleDescriptionStr(), warnMsg)
}

func (f *FwRule) effectiveRules() (inbound, outbound *FwRule) {
	if len(f.scope) == 0 {
		f.ruleWarning("has no effective inbound/outbound component, since its scope component is empty")
		return nil, nil
	}
	if f.Conn.IsEmpty() {
		f.ruleWarning("has no effective inbound/outbound component, since its inferred services are empty")
		return nil, nil
	}
	return f.getInboundRule(), f.getOutboundRule()
}

func (f *FwRule) getInboundRule() *FwRule {
	// if action is OUT -> return nil
	if f.Direction == string(nsx.RuleDirectionOUT) {
		f.ruleWarning("has no effective inbound component, since its direction is OUT only")
		return nil
	}
	if len(f.dstVMs) == 0 {
		f.ruleWarning("has no effective inbound component, since its dest-vms component is empty")
		return nil
	}
	if len(f.srcVMs) == 0 {
		f.ruleWarning("has no effective inbound component, since its target src-vms component is empty")
		return nil
	}

	// inbound rule operates on intersection(dest, scope)
	newDest := endpoints.Intersection(f.dstVMs, f.scope)
	if len(newDest) == 0 {
		f.ruleWarning("has no effective inbound component, since its intersction for dest & scope is empty")
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
		Conn:           f.Conn,
		Action:         f.Action,
		Direction:      string(nsx.RuleDirectionIN),
		OrigRuleObj:    f.OrigRuleObj,
		RuleID:         f.RuleID,
		secPolicyName:  f.secPolicyName,
		Priority:       f.Priority,
	}
}

func (f *FwRule) getOutboundRule() *FwRule {
	// if action is IN -> return nil
	if f.Direction == string(nsx.RuleDirectionIN) {
		f.ruleWarning("has no effective outbound component, since its direction is IN only")
		return nil
	}
	if len(f.srcVMs) == 0 {
		f.ruleWarning("has no effective outbound component, since its src vms component is empty")
		return nil
	}

	if len(f.dstVMs) == 0 {
		f.ruleWarning("has no effective outbound component, since its target dst vms component is empty")
		return nil
	}

	// outbound rule operates on intersection(src, scope)
	newSrc := endpoints.Intersection(f.srcVMs, f.scope)
	if len(newSrc) == 0 {
		f.ruleWarning("has no effective outbound component, since its intersction for src & scope is empty")
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
		Conn:           f.Conn,
		Action:         f.Action,
		Direction:      string(nsx.RuleDirectionOUT),
		OrigRuleObj:    f.OrigRuleObj,
		RuleID:         f.RuleID,
		secPolicyName:  f.secPolicyName,
		Priority:       f.Priority,
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
	return common.JoinStringifiedSlice(vms, common.CommaSeparator)
}

// return a string representation of a single rule
// groups are interpreted to VM members in this representation
func (f *FwRule) String() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s, scope: %s, sec-policy: %s",
		f.RuleID, vmsString(f.srcVMs), vmsString(f.dstVMs), f.Conn.String(), string(f.Action), f.Direction, vmsString(f.scope), f.secPolicyName)
}

func (f *FwRule) effectiveRuleStr() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s, sec-policy: %s",
		f.RuleID, vmsString(f.srcVMs), vmsString(f.dstVMs), f.Conn.String(), string(f.Action), f.Direction, f.secPolicyName)
}

func getDefaultRuleScope(r *collector.FirewallRule) string {
	return common.JoinCustomStrFuncSlice(r.AppliedTos,
		func(r nsx.ResourceReference) string {
			if r.TargetDisplayName != nil {
				return *r.TargetDisplayName
			}
			return ""
		}, common.CommaSeparator)
}

// shorten long strings in output, to enable readable table of the input fw-rules
func trimmedString(s string) string {
	const (
		strLenLimit = 30
		trimmedStr  = "..."
	)
	if len(s) > strLenLimit {
		// shorten long strings in output, to enable readable table of the input fw-rules
		s = s[0:strLenLimit] + trimmedStr
	}
	return s
}

func (f *FwRule) pathToShortPathString(path string) string {
	const (
		pathSep = "/"
	)
	var res string
	// get display name from path when possible
	if name, ok := f.dfwRef.pathsToDisplayNames[path]; ok {
		res = name
	} else {
		// shorten the path str in output
		pathElems := strings.Split(path, pathSep)
		if len(pathElems) == 0 {
			return ""
		}
		res = pathElems[len(pathElems)-1]
	}
	return trimmedString(res)
}

func (f *FwRule) getShortPathsString(paths []string) string {
	return common.JoinCustomStrFuncSlice(paths,
		func(p string) string { return f.pathToShortPathString(p) }, common.CommaSeparator)
}

func getSrcOrDstExcludedStr(groupsStr string) string {
	return fmt.Sprintf("exclude(%s)", groupsStr)
}

func (f *FwRule) getSrcString() string {
	srcGroups := f.getShortPathsString(f.OrigRuleObj.SourceGroups)
	if f.OrigRuleObj.SourcesExcluded {
		return getSrcOrDstExcludedStr(srcGroups)
	}
	return srcGroups
}

func (f *FwRule) getDstString() string {
	dstGroups := f.getShortPathsString(f.OrigRuleObj.DestinationGroups)
	if f.OrigRuleObj.DestinationsExcluded {
		return getSrcOrDstExcludedStr(dstGroups)
	}
	return dstGroups
}

func getRulesHeader() []string {
	return []string{
		"ruleID",
		"ruleName",
		"src",
		"dst",
		"services",
		"action",
		"direction",
		"scope",
		"sec-policy",
		"Category",
	}
}

// originalRuleComponentsStr returns a string representation of a single rule with original attribute values (including groups)
func (f *FwRule) originalRuleComponentsStr() []string {
	const (
		anyStr = "ANY"
	)
	if f.OrigRuleObj == nil && f.origDefaultRuleObj == nil {
		f.ruleWarning("has no origRuleObj or origDefaultRuleObj")
		return []string{}
	}

	// if this is a "default rule" from category with ConnectivityPreference configured,
	// the rule object is of different type
	if f.OrigRuleObj == nil && f.origDefaultRuleObj != nil {
		return []string{
			*f.origDefaultRuleObj.Id,
			*f.origDefaultRuleObj.DisplayName,
			// The default rule that gets created will be a any-any rule and applied
			// to entities specified in the scope of the security policy.
			anyStr,
			anyStr,
			anyStr,
			string(*f.origDefaultRuleObj.Action),
			string(f.origDefaultRuleObj.Direction),
			getDefaultRuleScope(f.origDefaultRuleObj),
			f.secPolicyName,
			f.secPolicyCategory,
		}
	}

	name := ""
	if f.OrigRuleObj.DisplayName != nil {
		name = *f.OrigRuleObj.DisplayName
	}
	return []string{
		f.RuleIDStr(),
		name,
		f.getSrcString(),
		f.getDstString(),
		f.servicesString(),
		string(f.Action), f.Direction,
		strings.Join(f.OrigRuleObj.Scope, common.CommaSeparator),
		f.secPolicyName,
		f.secPolicyCategory,
	}
}

func (f *FwRule) servicesString() string {
	var serviceEntriesStr, servicesStr string
	serviceEntriesStr = trimmedString(common.JoinStringifiedSlice(f.OrigRuleObj.ServiceEntries, common.CommaSeparator))
	servicesStr = f.getShortPathsString(f.OrigRuleObj.Services)
	return common.JoinNonEmpty([]string{serviceEntriesStr, servicesStr}, common.CommaSeparator)
}
