package dfw

import (
	"fmt"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// return a string representation of a single rule
// groups are interpreted to VM members in this representation
func (f *FwRule) String() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s, scope: %s, sec-policy: %s",
		f.RuleID, vmsString(f.SrcVMs), vmsString(f.DstVMs), f.Conn.String(), string(f.Action), f.direction, vmsString(f.scope), f.secPolicyName)
}

func (f *FwRule) effectiveRuleStr() string {
	return fmt.Sprintf("ruleID: %d, src: %s, dst: %s, conn: %s, action: %s, direction: %s, sec-policy: %s",
		f.RuleID, vmsString(f.SrcVMs), vmsString(f.DstVMs), f.Conn.String(), string(f.Action), f.direction, f.secPolicyName)
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
		strings.Join(f.OrigRuleObj.Scope, common.CommaSeparator),
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

func (f *FwRule) servicesString() string {
	var serviceEntriesStr, servicesStr string
	serviceEntriesStr = trimmedString(common.JoinStringifiedSlice(f.OrigRuleObj.ServiceEntries, common.CommaSeparator))
	servicesStr = f.getShortPathsString(f.OrigRuleObj.Services)
	return common.JoinNonEmpty([]string{serviceEntriesStr, servicesStr}, common.CommaSeparator)
}

func vmsString(vms []topology.Endpoint) string {
	return common.JoinStringifiedSlice(vms, common.CommaSeparator)
}
