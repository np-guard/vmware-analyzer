package model

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"

	"strings"
)

func inferDisjointGroups(groups []*collector.Group, givenHints *symbolicexpr.Hints,
	inferHints bool) *symbolicexpr.Hints {
	return givenHints
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
		return common.GenerateTableString(header, lines, &common.TableOptions{SortLines: true, Colors: color}) + "\n"
	}
	return ""
}
