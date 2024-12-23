package symbolicexpr

import (
	"fmt"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
)

func (path *SymbolicPath) string() string {
	return path.Conn.String() + " from " + path.Src.string() + " to " + path.Dst.string()
}

// if the source or destination is empty then so is the entire path
func (path *SymbolicPath) isEmpty() bool {
	return path.Conn.IsEmpty() || path.Src.isEmptySet() || path.Dst.isEmptySet()
}

// checks whether paths are disjoint. This is the case when one of the path's components (src, dst, conn) are disjoint
func (path *SymbolicPath) disJointPaths(other *SymbolicPath) bool {
	return (*path).Conn.Intersect((*other).Conn).IsEmpty() || (*path).Src.disjoint(&(*other).Src) ||
		(*path).Dst.disjoint(&(*other).Dst)
}

func (paths *SymbolicPaths) String() string {
	if len(*paths) == 0 {
		return emptySet
	}
	res := make([]string, len(*paths))
	for i, path := range *paths {
		res[i] = path.string()
	}
	return strings.Join(res, "\n")
}

func (paths *SymbolicPaths) removeEmpty() *SymbolicPaths {
	newPaths := SymbolicPaths{}
	for _, path := range *paths {
		if !path.isEmpty() {
			newPaths = append(newPaths, path)
		}
	}
	return &newPaths
}

func (paths *SymbolicPaths) removeTautology() *SymbolicPaths {
	newPaths := SymbolicPaths{}
	for _, path := range *paths {
		if !path.isEmpty() {
			newPath := &SymbolicPath{Src: path.Src.removeTautology(), Dst: path.Dst.removeTautology(), Conn: path.Conn}
			newPaths = append(newPaths, newPath)
		}
	}
	return &newPaths
}

// ComputeAllowGivenDenies converts a set of symbolic allow and deny paths (given as type SymbolicPaths)
// the resulting allow paths in SymbolicPaths
// The motivation here is to unroll allow rule given higher priority deny rule
// computation for each allow symbolicPath:
// computeAllowGivenAllowHigherDeny is called iteratively for each deny path, on applied on the previous result
// the result is the union of the above computation for each allow path
// if there are no allow paths then no paths are allowed - the empty set will be returned
// if there are no deny paths then allowPaths are returned as is
func ComputeAllowGivenDenies(allowPaths, denyPaths *SymbolicPaths) *SymbolicPaths {
	if len(*denyPaths) == 0 {
		return allowPaths
	}
	res := SymbolicPaths{}
	for _, allowPath := range *allowPaths {
		relevantDenyPaths := SymbolicPaths{}
		for _, denyPath := range *denyPaths {
			if !allowPath.disJointPaths(denyPath) {
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
				thisComputed := *computeAllowGivenAllowHigherDeny(*computedAllow, *denyPath)
				newComputedAllowPaths = append(newComputedAllowPaths, thisComputed...)
			}
			computedAllowPaths = newComputedAllowPaths
		}
		res = append(res, computedAllowPaths...)
		fmt.Println()
	}
	return &res
}

// algorithm described in README of symbolicexpr
func computeAllowGivenAllowHigherDeny(allowPath, denyPath SymbolicPath) *SymbolicPaths {
	resAllowPaths := SymbolicPaths{}
	for _, srcAtom := range denyPath.Src {
		if !srcAtom.isTautology() {
			srcAtomNegate := srcAtom.negate().(atomicTerm)
			resAllowPaths = append(resAllowPaths, &SymbolicPath{Src: *allowPath.Src.copy().add(&srcAtomNegate),
				Dst: allowPath.Dst, Conn: allowPath.Conn})
		}
	}
	for _, dstAtom := range denyPath.Dst {
		if !dstAtom.isTautology() {
			dstAtomNegate := dstAtom.negate().(atomicTerm)
			resAllowPaths = append(resAllowPaths, &SymbolicPath{Src: allowPath.Src, Dst: *allowPath.Dst.copy().add(&dstAtomNegate),
				Conn: allowPath.Conn})
		}
	}
	if !denyPath.Conn.IsAll() { // Connection of deny path is not tautology
		resAllowPaths = append(resAllowPaths, &SymbolicPath{Src: allowPath.Src, Dst: allowPath.Dst,
			Conn: allowPath.Conn.Subtract(denyPath.Conn)})
	}
	return resAllowPaths.removeEmpty().removeTautology()
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
