package dfw

import (
	"fmt"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

// return a string representation of a single rule
// groups are interpreted to VM members in this representation

func (f *EvaluatedFWRule) evaluatedRuleStr() string {
	lines := []string{ // lines for rule str
		fmt.Sprintf("rule ID: %d", f.RuleObj.RuleID),
		fmt.Sprintf("Is effective: %t", f.IsEffective),
		fmt.Sprintf("operates on: %s", common.JoinStringifiedSlice(f.OperatesOn, common.CommaSpaceSeparator)),
		fmt.Sprintf("direction: %s", f.Direction),
		fmt.Sprintf("src interpreted endpoints object: \n%s", f.RuleObj.Src.String()),
		fmt.Sprintf("dst interpreted endpoints object: \n%s", f.RuleObj.Dst.String()),
		fmt.Sprintf("scope interpreted endpoints object: \n%s", f.RuleObj.Scope.String()),
		fmt.Sprintf("connection: %s", f.RuleObj.Conn.String()),
		fmt.Sprintf("action: %s", f.RuleObj.Action),
		fmt.Sprintf("secPolicyName: %s", f.RuleObj.secPolicyName),
		fmt.Sprintf("secPolicyCategory: %s", f.RuleObj.secPolicyCategory),
	}

	return strings.Join(lines, common.NewLine)
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

func (f *FwRule) scopeStr() string {
	if f.Scope.IsAllGroups {
		return common.AnyStr
	}
	return common.SortedJoinCustomStrFuncSlice(f.Scope.Groups,
		func(g *collector.Group) string { return *g.DisplayName }, common.CommaSeparator)
}

// originalRuleComponentsStr returns a string representation of a single rule with original attribute values (including groups),
// matching to fields as returned from getRulesHeader()
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
			getDefaultRuleScopeStr(f.origDefaultRuleObj),
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
		string(f.Action), f.direction,
		f.scopeStr(),
		f.secPolicyName,
		f.secPolicyCategory,
	}
}

func getDefaultRuleScopeStr(r *collector.FirewallRule) string {
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
	return common.SortedJoinCustomStrFuncSlice(paths,
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

func (f *FwRule) servicesString() string {
	var serviceEntriesStr, servicesStr string
	serviceEntriesStr = trimmedString(common.JoinStringifiedSlice(f.OrigRuleObj.ServiceEntries, common.CommaSeparator))
	servicesStr = f.getShortPathsString(f.OrigRuleObj.Services)
	return common.JoinNonEmpty([]string{serviceEntriesStr, servicesStr}, common.CommaSeparator)
}
