package model

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"

	"sort"
	"strings"
)

// todo: make more efficient https://github.com/np-guard/vmware-analyzer/issues/436
func inferDisjointGroups(groups []*collector.Group, inferHints bool) *symbolicexpr.Hints {
	if !inferHints {
		return &symbolicexpr.Hints{}
	}
	// sort the groups by name so that the results is always the same (and not e.g. sometimes [sly][gry] and sometimes [gry][sly]
	// includes only groups with VMs
	nameToGroup := map[string]*collector.Group{}
	names := []string{}
	for _, group := range groups {
		if len(group.VMMembers) == 0 {
			continue
		}
		nameToGroup[group.String()] = group
		names = append(names, group.String())
	}
	sort.Strings(names)
	groupsDisjoint := [][]string{}
	for outerIndex := range names {
		outerGroup := nameToGroup[names[outerIndex]]
		for innerIndex := outerIndex + 1; innerIndex < len(groups); innerIndex++ {
			innerGroup := nameToGroup[names[innerIndex]]
			if groupsVMDisjoint(outerGroup, innerGroup) {
				groupsDisjoint = append(groupsDisjoint, []string{outerGroup.String(), innerGroup.String()})
			}
		}
	}
	// have pairs in this stage
	return &symbolicexpr.Hints{GroupsDisjoint: groupsDisjoint}
}

func groupsVMDisjoint(group1, group2 *collector.Group) bool {
	for _, vm1 := range group1.VMMembers {
		for _, vm2 := range group2.VMMembers {
			if vm1.String() == vm2.String() {
				return false
			}
		}
	}
	return true
}

func getAllHints(givenHints, inferredHints *symbolicexpr.Hints) *symbolicexpr.Hints {
	allDisjointGroups := make([][]string, 0, len(givenHints.GroupsDisjoint)+len(inferredHints.GroupsDisjoint))
	allDisjointGroups = append(allDisjointGroups, givenHints.GroupsDisjoint...)
	allDisjointGroups = append(allDisjointGroups, inferredHints.GroupsDisjoint...)
	return &symbolicexpr.Hints{GroupsDisjoint: allDisjointGroups}
}

func getHintsStr(hints *symbolicexpr.Hints, isGivenHints, color bool) string {
	headerStr := "Provided by user"
	if !isGivenHints {
		headerStr = "Automatically inferred based on groups' snapshot"
	}
	header := []string{headerStr}
	lines := [][]string{}
	for _, disjointGroups := range hints.GroupsDisjoint {
		lines = append(lines, []string{strings.Join(disjointGroups, ", ")})
	}
	if len(lines) > 0 {
		return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color})
	}
	return ""
}
