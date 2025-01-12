package symbolicexpr

import (
	"fmt"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
)

func (path *SymbolicPath) String() string {
	return path.Conn.String() + " from " + path.Src.string() + " to " + path.Dst.string()
}

// if the source or destination is empty then so is the entire path
func (path *SymbolicPath) isEmpty(hints *Hints) bool {
	return path.Conn.IsEmpty() || path.Src.isEmptySet(hints) || path.Dst.isEmptySet(hints)
}

// checks whether paths are disjoint. This is the case when one of the path's components (src, dst, conn) are disjoint
func (path *SymbolicPath) disjointPaths(other *SymbolicPath, hints *Hints) bool {
	return path.Conn.Intersect(other.Conn).IsEmpty() || path.Src.disjoint(&other.Src, hints) ||
		path.Dst.disjoint(&other.Dst, hints)
}

func (path *SymbolicPath) isSubset(other *SymbolicPath, hints *Hints) bool {
	return path.Conn.IsSubset(other.Conn) && path.Src.isSubset(&other.Src, hints) &&
		path.Dst.isSubset(&other.Dst, hints)
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
	res := make([]string, len(*paths))
	for i, path := range *paths {
		res[i] = path.String()
	}
	return strings.Join(res, "\n")
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

func (paths SymbolicPaths) removeIsSubsetPath(hints *Hints) SymbolicPaths {
	newPaths := SymbolicPaths{}
	for outerIndex, outerPath := range paths {
		addPath := true
		for innerIndex, innerPath := range paths {
			if innerIndex == outerIndex {
				continue
			}
			if innerPath.isSubset(outerPath, hints) && !(outerPath.isSubset(innerPath, hints) && outerIndex < innerIndex) {
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
				thisComputed = thisComputed.removeIsSubsetPath(hints)
				newComputedAllowPaths = append(newComputedAllowPaths, thisComputed...)
			}
			computedAllowPaths = newComputedAllowPaths.removeIsSubsetPath(hints)
		}
		res = append(res, computedAllowPaths...)
		fmt.Println()
	}
	res = res.removeIsSubsetPath(hints)
	return &res
}

// algorithm described in README of symbolicexpr
func computeAllowGivenAllowHigherDeny(allowPath, denyPath SymbolicPath, hints *Hints) *SymbolicPaths {
	resAllowPaths := &SymbolicPaths{}
	for _, srcAtom := range denyPath.Src {
		if !srcAtom.isTautology() {
			srcAtomNegate := srcAtom.negate().(atomicTerm)
			resAllowPaths = resAllowPaths.add(&SymbolicPath{Src: *allowPath.Src.copy().add(srcAtomNegate),
				Dst: allowPath.Dst, Conn: allowPath.Conn}, hints)
		}
	}
	for _, dstAtom := range denyPath.Dst {
		if !dstAtom.isTautology() {
			dstAtomNegate := dstAtom.negate().(atomicTerm)
			resAllowPaths = resAllowPaths.add(&SymbolicPath{Src: allowPath.Src, Dst: *allowPath.Dst.copy().add(dstAtomNegate),
				Conn: allowPath.Conn}, hints)
		}
	}
	if !denyPath.Conn.IsAll() { // Connection of deny path is not tautology
		resAllowPaths = resAllowPaths.add(&SymbolicPath{Src: allowPath.Src, Dst: allowPath.Dst,
			Conn: allowPath.Conn.Subtract(denyPath.Conn)}, hints)
	}
	// removes empty SymblicPaths; of non-empty paths removed redundant terms
	return resAllowPaths.removeRedundant(hints)
}

// ConvertFWRuleToSymbolicPaths given a rule, converts its src, dst and Conn to SymbolicPaths
func ConvertFWRuleToSymbolicPaths(rule *dfw.FwRule) *SymbolicPaths {
	resSymbolicPaths := SymbolicPaths{}
	tarmAny := Conjunction{tautology{}}
	srcTerms := getAtomicTermsForGroups(rule.SrcGroups)
	dstTerms := getAtomicTermsForGroups(rule.DstGroups)
	switch {
	case rule.IsAllSrcGroups && rule.IsAllDstGroups:
		resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: tarmAny, Dst: tarmAny, Conn: rule.Conn})
	case rule.IsAllSrcGroups:
		for _, dstTerm := range dstTerms {
			resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: tarmAny, Dst: Conjunction{dstTerm},
				Conn: rule.Conn})
		}
	case rule.IsAllDstGroups:
		for _, srcTerm := range srcTerms {
			resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: Conjunction{srcTerm}, Dst: tarmAny,
				Conn: rule.Conn})
		}
	default:
		for _, srcTerm := range srcTerms {
			for _, dstTerm := range dstTerms {
				resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: Conjunction{srcTerm},
					Dst: Conjunction{dstTerm}, Conn: rule.Conn})
			}
		}
	}
	return &resSymbolicPaths
}
