package model

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"

	"strings"
)

func inferDisjointGroups(groups []*collector.Group, givenHints *symbolicexpr.Hints,
	inferHints bool) (inferredHints, allHints *symbolicexpr.Hints) {
	return givenHints, givenHints
}

func getHintsStr(hints *symbolicexpr.Hints, isGivenHints, color bool) string {
	headerStr := "List of disjoint groups provided by user"
	if !isGivenHints {
		headerStr = "List of disjoint groups automatically inferred based on groups' snapshot"
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
