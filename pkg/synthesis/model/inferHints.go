package model

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

func inferDisjointGroups(groups []*collector.Group, givenHints *symbolicexpr.Hints,
	inferHints bool) (inferredHints, allHints *symbolicexpr.Hints) {
	return givenHints, givenHints
}
