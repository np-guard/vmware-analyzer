package synthesis

import (
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/endpoints"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
)

// AbstractModelSyn is an abstraction from which the synthesis is performed
type AbstractModelSyn struct {
	vms        []*endpoints.VM
	epToGroups map[*endpoints.VM][]*collector.Group
	// todo: add similar maps to OS, hostname

	// if synthesizeAdmin is true, rules will be translated to allow only starting with category MinNonAdminCategory();
	// categories before that category rules' also include pass, deny and priority (default: false - all categories are "Allow only")
	// todo: "JumpTaoApp" -> pass. Not correct in all scenarios, but is good enough for what we need and for POC
	synthesizeAdmin bool
	policy          []*symbolicPolicy // with default deny todo: should be *symbolicPolicy?
	defaultDenyRule *dfw.FwRule
}

// Tags map from tag's name to the tag
type Tags map[string]*collector.Tag

// symbolicRule input to synthesis. Synthesis very likely to non-prioritized only allow policy
//
//nolint:all
type symbolicRule struct { // original rule
	origRule *dfw.FwRule // original rule
	// category; for reference, e.g. in the labels or documentation of the synthesized objects
	// a pass rule is interpreted as deny for the current category
	origRuleCategory  collector.DfwCategory
	origSymbolicPaths *symbolicexpr.SymbolicPaths // symbolic presentation paths defined by the original rule
	// The following refers to conversion of original allow rule to symbolic paths, as follows:
	// Assuming there are only allow (non-prioritized, of course) policy.
	// This is relevant only for allow policy (nil otherwise)
	// and only for categories greater than allowOnlyFromCategory
	allowOnlyRulePaths symbolicexpr.SymbolicPaths
	// allow only list after optimization in global scope - e.g. a path is removed if there is a path in another
	// rule that is a super set of it.
	// In case of two identical paths - the paths stays in the higher priority rule
	optimizedAllowOnlyPaths symbolicexpr.SymbolicPaths
}

func (r *symbolicRule) category() collector.DfwCategory {
	return r.origRuleCategory
}
func (r *symbolicRule) priority() int {
	return r.origRule.Priority
}
func (r *symbolicRule) ruleID() int {
	return r.origRule.RuleID
}

type symbolicPolicy struct {
	inbound  []*symbolicRule // ordered list inbound symbolicRule
	outbound []*symbolicRule // ordered list outbound symbolicRule
}

func (policy *symbolicPolicy) isInbound(r *symbolicRule) bool {
	return slices.Contains(policy.inbound, r)
}

// sorting the policies before synthesis, for the user to be intuitive:
// by categories, by priority, by rule Id, etc...
func (policy *symbolicPolicy) sortRules() []*symbolicRule {
	symbolicOrigRulesSortFunc := func(r1, r2 *symbolicRule) int {
		switch {
		case r1.category() != r2.category():
			return int(r1.category()) - int(r2.category())
		case r1.priority() != r2.priority():
			return r1.priority() - r2.priority()
		case r1.ruleID() != r2.ruleID():
			return r1.ruleID() - r2.ruleID()
		case policy.isInbound(r1):
			return 1
		default:
			return -1
		}
	}
	res := slices.Concat(policy.inbound, policy.outbound)
	slices.SortStableFunc(res, symbolicOrigRulesSortFunc)
	return res
}

// maps used by AbstractModelSyn

// Segments topology; map from segment name to the segment
type Segments map[string]*collector.Segment

func strAbstractModel(abstractModel *AbstractModelSyn, color bool) string {
	var strArray []string
	strArray = append(strArray)
	return "\nAbstract Model Details\n=======================\n" +
		strGroupsStr(abstractModel.epToGroups, color) + strAllowOnlyPolicy(abstractModel.policy[0], color)
}

func strGroupsStr(epsToGroups map[*endpoints.VM][]*collector.Group, color bool) string {
	// 1. gets a list of groups
	groupsMap := map[string]*collector.Group{}
	for _, groups := range epsToGroups {
		for _, group := range groups {
			if _, ok := groupsMap[*group.DisplayName]; ok {
				continue
			}
			groupsMap[*group.DisplayName] = group
		}
	}
	// 2. gathers the data
	// todo: identify here cases in which we were unable to process expr
	header := []string{"Group", "Expression", "VM"}
	lines := make([][]string, len(groupsMap))
	i := 0
	for name, group := range groupsMap {
		groupExprStr := ""
		groupVmNames := make([]string, len(group.VMMembers))
		if len(group.Expression) > 0 {
			groupExprStr = group.Expression.String()
		}
		for j, vm := range group.VMMembers {
			groupVmNames[j] = *vm.DisplayName
		}
		newLine := []string{name, groupExprStr, strings.Join(groupVmNames, ", ")}
		lines[i] = newLine
		i++
	}
	return "\nGroups' definition\n~~~~~~~~~~~~~~~~~~\n" +
		common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
}
