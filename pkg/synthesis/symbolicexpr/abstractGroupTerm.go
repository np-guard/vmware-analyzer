package symbolicexpr

import (
	"fmt"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// abstraction of an NSX originate group or over VMs originating from an NSX internal cidr

// following 4 functions are false since an abstractGroupTerm is an abstraction of non-trivial groups

func (abstractGroupTerm) IsTautology() bool {
	return false
}

func (abstractGroupTerm) IsContradiction() bool {
	return false
}

func (abstractGroupTerm) IsAllGroups() bool {
	return false
}

func (abstractGroupTerm) IsNoGroup() bool {
	return false
}

//

func (abstractGroup abstractGroupTerm) name() string {
	return abstractGroup.group.Name()
}

func (abstractGroupTerm) GetBlock() *netset.IPBlock {
	return nil
}

// Evaluates group and translates it into []*Conjunction
// If group has no expr or evaluation expr fails then uses the group names in  Conjunction
func getConjunctionForGroups(groups []*collector.Group, groupToConjunctions map[string][]*Conjunction,
	ruleID int) []*Conjunction {
	res := []*Conjunction{}
	for _, group := range groups {
		// todo: treat negation properly
		if cachedGroupConj, ok := groupToConjunctions[group.Name()]; ok {
			res = append(res, cachedGroupConj...)
			continue
		}
		// not in cache
		// default: Conjunction defined via group only
		groupConj := []*Conjunction{{groupAtomicTerm{abstractGroupTerm: abstractGroupTerm{group: group},
			atomicTerm: atomicTerm{neg: false}}}}
		synthesisUseGroup := fmt.Sprintf("group %s, referenced by FW rule with ID %d, "+
			"synthesis will be based only on its name", group.Name(), ruleID)
		// if group has a tag based supported expression then considers the tags
		if len(group.Expression) > 0 {
			tagConj := GetTagConjunctionForExpr(&group.Expression, group.Name())
			if tagConj != nil {
				groupConj = tagConj
			} else {
				logging.Debugf("for %s", synthesisUseGroup)
			}
		} else {
			logging.Debugf("No expression is attached to %s", synthesisUseGroup)
		}
		groupToConjunctions[group.Name()] = groupConj
		res = append(res, groupConj...)
	}
	return res
}
