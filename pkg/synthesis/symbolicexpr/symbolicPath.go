package symbolicexpr

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func (path *SymbolicPath) String() string {
	return "src: " + path.Src.String() + " dst: " + path.Dst.String() + " conn: " + path.Conn.String()
}

func (path *SymbolicPath) TableString() []string {
	return []string{path.Src.String(), path.Dst.String(), path.Conn.String()}
}

// if the source or destination is empty then so is the entire path
func (path *SymbolicPath) isEmpty(hints *Hints) bool {
	return path.Conn.IsEmpty() || path.Src.isEmpty(hints) || path.Dst.isEmpty(hints)
}

// checks whether paths are disjoint. This is the case when one of the path's components (src, dst, conn) are disjoint
func (path *SymbolicPath) disjointPaths(other *SymbolicPath, hints *Hints) bool {
	return path.Conn.Intersect(other.Conn).IsEmpty() || path.Src.disjoint(&other.Src, hints) ||
		path.Dst.disjoint(&other.Dst, hints)
}

func (path *SymbolicPath) isSuperset(other *SymbolicPath, hints *Hints) bool {
	return other.Conn.IsSubset(path.Conn) && path.Src.isSuperset(&other.Src, hints) &&
		path.Dst.isSuperset(&other.Dst, hints)
}

func (paths *SymbolicPaths) add(newPath *SymbolicPath, hints *Hints) *SymbolicPaths {
	if newPath.isEmpty(hints) {
		return paths
	}
	res := append(*paths, newPath)
	return &res
}

func (paths *SymbolicPaths) String() string {
	if len(*paths) == 0 {
		return emptySet
	}
	return common.JoinStringifiedSlice(*paths, common.NewLine)
}

// Given SymbolicPaths, removes redundant terms from each SymbolicPath
// a term is redundant if it is a tautology or if it is implied by other terms given hints;
// e.g., given that Slytherin and Gryffindor are disjoint, = Gryffindor implies != Slytherin
func (paths *SymbolicPaths) removeRedundant(hints *Hints) *SymbolicPaths {
	newPaths := SymbolicPaths{}
	for _, path := range *paths {
		newPaths = append(newPaths, path.removeRedundant(hints))
	}
	return &newPaths
}

// RemoveIsSubsetPath remove any path that is a subset of another part in paths
func (paths SymbolicPaths) RemoveIsSubsetPath(hints *Hints) SymbolicPaths {
	newPaths := SymbolicPaths{}
	for outerIndex, outerPath := range paths {
		addPath := true
		for innerIndex, innerPath := range paths {
			if innerIndex == outerIndex {
				continue
			}
			if innerPath.isSuperset(outerPath, hints) && !(outerPath.isSuperset(innerPath, hints) && outerIndex < innerIndex) {
				addPath = false
				break
			}
		}
		if addPath {
			newPaths = append(newPaths, outerPath)
		}
	}
	return newPaths
}

func (path *SymbolicPath) removeRedundant(hints *Hints) *SymbolicPath {
	return &SymbolicPath{Src: path.Src.removeRedundant(hints), Dst: path.Dst.removeRedundant(hints), Conn: path.Conn}
}

// ComputeAllowGivenDenies converts a set of symbolic allow and deny paths (given as type SymbolicPaths)
// the resulting allow paths in SymbolicPaths
// The motivation here is to unroll allow rule given higher priority deny rule
// computation for each allow symbolicPath:
// computeAllowGivenAllowHigherDeny is called iteratively for each deny path, applied on the previous result
// the result is the union of the above computation for each allow path
// if there are no allow paths then no paths are allowed - the empty set will be returned
// if there are no deny paths then allowPaths are returned as is
// all optimizations are documented in README
func ComputeAllowGivenDenies(allowPaths, denyPaths *SymbolicPaths, hints *Hints) *SymbolicPaths {
	if len(*denyPaths) == 0 {
		return allowPaths
	}
	res := SymbolicPaths{}
	for _, allowPath := range *allowPaths {
		// if the "allow" and "deny" paths are disjoint, then the "deny" has no effect and could be ignored
		// e.g.   allow: a to d TCP deny: e to d on UDP  - the "deny" has no effect
		relevantDenyPaths := SymbolicPaths{}
		for _, denyPath := range *denyPaths {
			if !allowPath.disjointPaths(denyPath, hints) {
				relevantDenyPaths = append(relevantDenyPaths, denyPath)
			}
		}
		if len(relevantDenyPaths) == 0 { // the denys paths are not relevant for this allow. This allow path remains as is
			res = append(res, allowPath)
			continue
		}
		var computedAllowPaths, newComputedAllowPaths SymbolicPaths
		newComputedAllowPaths = SymbolicPaths{allowPath}
		for _, denyPath := range relevantDenyPaths {
			computedAllowPaths = newComputedAllowPaths
			newComputedAllowPaths = SymbolicPaths{}
			for _, computedAllow := range computedAllowPaths {
				thisComputed := *computeAllowGivenAllowHigherDeny(*computedAllow, *denyPath, hints)
				thisComputed = thisComputed.RemoveIsSubsetPath(hints)
				newComputedAllowPaths = append(newComputedAllowPaths, thisComputed...)
			}
			computedAllowPaths = newComputedAllowPaths.RemoveIsSubsetPath(hints)
		}
		res = append(res, computedAllowPaths...)
	}
	res = res.RemoveIsSubsetPath(hints)
	return &res
}

// algorithm described in README of symbolicexpr
func computeAllowGivenAllowHigherDeny(allowPath, denyPath SymbolicPath, hints *Hints) *SymbolicPaths {
	resAllowPaths := &SymbolicPaths{}
	// In the below, note that Tautology (0.0.0.0/0) also returns true for IsAllGroups
	for _, srcAtom := range denyPath.Src {
		if !srcAtom.IsAllGroups() {
			srcAtomNegate := srcAtom.negate()
			resAllowPaths = resAllowPaths.add(&SymbolicPath{Src: *allowPath.Src.copy().add(srcAtomNegate),
				Dst: allowPath.Dst, Conn: allowPath.Conn}, hints)
		}
	}
	for _, dstAtom := range denyPath.Dst {
		if !dstAtom.IsAllGroups() {
			dstAtomNegate := dstAtom.negate()
			resAllowPaths = resAllowPaths.add(&SymbolicPath{Src: allowPath.Src, Dst: *allowPath.Dst.copy().add(dstAtomNegate),
				Conn: allowPath.Conn}, hints)
		}
	}
	if !denyPath.Conn.IsAll() { // Connection of deny path is not tautology
		resAllowPaths = resAllowPaths.add(&SymbolicPath{Src: allowPath.Src, Dst: allowPath.Dst,
			Conn: allowPath.Conn.Subtract(denyPath.Conn)}, hints)
	}
	// removes empty SymbolicPaths; of non-empty paths removed redundant terms
	return resAllowPaths.removeRedundant(hints)
}

// ConvertFWRuleToSymbolicPaths given a rule, converts its src, dst and Conn to SymbolicPaths
func ConvertFWRuleToSymbolicPaths(isInbound bool, rule *dfw.FwRule, groupToConjunctions map[string][]*Conjunction) *SymbolicPaths {
	resSymbolicPaths := SymbolicPaths{}
	srcConjunctions := getConjunctionsSrcOrDst(rule, groupToConjunctions, rule.Src.IsAllGroups, rule.Src.Groups, rule.Src.Blocks)
	dstConjunctions := getConjunctionsSrcOrDst(rule, groupToConjunctions, rule.Dst.IsAllGroups, rule.Dst.Groups, rule.Dst.Blocks)
	if !rule.Scope.IsAllGroups {
		scopeConjunctions := getConjunctionsSrcOrDst(rule, groupToConjunctions, false, rule.Scope.Groups, nil)
		if isInbound {
			dstConjunctions = append(dstConjunctions, scopeConjunctions...)
		} else { // outbound
			srcConjunctions = append(srcConjunctions, scopeConjunctions...)
		}
	}
	for _, srcConjunction := range srcConjunctions {
		for _, dstConjunction := range dstConjunctions {
			resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: *srcConjunction,
				Dst: *dstConjunction, Conn: rule.Conn})
		}
	}
	return &resSymbolicPaths
}

func getConjunctionsSrcOrDst(rule *dfw.FwRule, groupToConjunctions map[string][]*Conjunction,
	isAllGroups bool, groups []*collector.Group, ruleBlocks []*topology.RuleIPBlock) (res []*Conjunction) {
	ipBlockConjunctions, isTautology := getConjunctionForIPBlock(ruleBlocks)
	res = append(res, ipBlockConjunctions...)
	switch {
	case isTautology:
		return res // if 0.0.0.0/0 then this is the only relevant input
	case isAllGroups:
		res = append(res, &Conjunction{allGroup{}})
	default:
		res = append(res, getConjunctionForGroups(groups, groupToConjunctions, rule.RuleID)...)
	}
	return
}
