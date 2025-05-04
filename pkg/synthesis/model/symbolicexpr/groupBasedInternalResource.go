package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// groupBasedInternalResource represents term over group based internal resources - groupTerm, tagTerm
func (groupBasedInternalResource) getInternalBlock() *netset.IPBlock {
	return nil
}

// Evaluates group and translates it into []*Conjunction
// If group has no expr or evaluation expr fails then uses the group names in  Conjunction
func getConjunctionForGroups(containerModel *collector.ResourcesContainerModel, isExclude bool, groups []*collector.Group,
	groupToConjunctions map[string][]*Conjunction, ruleID int) []*Conjunction {
	res := []*Conjunction{}
	for _, group := range groups {
		key := group.Name()
		if isExclude {
			key = "not-" + key
		}
		// todo: treat negation properly
		if cachedGroupConj, ok := groupToConjunctions[key]; ok {
			res = append(res, cachedGroupConj...)
			continue
		}
		// not in cache
		// default: Conjunction defined via group only
		groupConj := []*Conjunction{{groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: isExclude}}}}
		synthesisUseGroup := fmt.Sprintf("group %s, referenced by FW rule with ID %d, "+
			"synthesis will be based only on its name", group.Name(), ruleID)
		// if group has a tag based supported expression then considers the tags
		if len(group.Expression) > 0 {
			tagConj := GetConjunctionFromExpr(containerModel, isExclude, &group.Expression, group.Name())
			if tagConj != nil {
				groupConj = tagConj
			} else {
				logging.Debugf("for %s", synthesisUseGroup)
			}
		} else {
			logging.Debugf("No expression is attached to %s", synthesisUseGroup)
		}
		groupToConjunctions[key] = groupConj
		res = append(res, groupConj...)
	}
	return res
}

// return the []atomic corresponding to a given condition
func getAtomicsForPath(containerModel *collector.ResourcesContainerModel,
	isExcluded bool, pathExpr *collector.PathExpression, group string) []atomic {
	res := []atomic{}
	for _, path := range pathExpr.Paths {
		groupOfPath := containerModel.FindGroupByPath(path)
		segmentOfPath := containerModel.GetSegment(path)
		switch {
		case groupOfPath != nil:
			res = append(res, groupAtomicTerm{group: groupOfPath, atomicTerm: atomicTerm{neg: isExcluded}})
		case segmentOfPath != nil:
			segment, err := configuration.ProcessSegment(segmentOfPath)
			if err != nil {
				debugMsg(group, err.Error())
			}
			res = append(res, SegmentTerm{segment: segment, atomicTerm: atomicTerm{neg: isExcluded}})
		default:
			debugMsg(group, fmt.Sprintf("includes a path %v which is not the current supported group or segment", path))
		}
	}
	return res
}
