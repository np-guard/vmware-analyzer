package symbolicexpr

import (
	"fmt"
	"github.com/np-guard/models/pkg/netset"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
)

func (path *SymbolicPath) string() string {
	return path.Src.string() + " to " + path.Dst.string() + " " + path.Conn.String()
}

// if the source or destination is empty then so is the entire path
func (path *SymbolicPath) isEmpty() bool {
	return path.Src.isEmptySet() || path.Dst.isEmptySet()
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
		var computedAllowPaths, newComputedAllowPaths SymbolicPaths
		newComputedAllowPaths = SymbolicPaths{allowPath}
		for _, denyPath := range *denyPaths {
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
	// in case deny path is open from both ends - empty set of allow paths, as will be the result
	// assumption: if more than one term, then none is tautology
	for _, srcAtom := range denyPath.Src {
		if !srcAtom.isTautology() {
			srcAtomNegate := srcAtom.negate().(atomicTerm)
			if allowPath.Src.isTautology() {
				resAllowPaths = append(resAllowPaths, &SymbolicPath{Src: Conjunction{&srcAtomNegate}, Dst: allowPath.Dst,
					Conn: netset.AllTransports()})
			} else {
				resAllowPaths = append(resAllowPaths, &SymbolicPath{Src: *allowPath.Src.copy().add(&srcAtomNegate),
					Dst: allowPath.Dst, Conn: netset.AllTransports()})
			}
		}
	}
	for _, dstAtom := range denyPath.Dst {
		if !dstAtom.isTautology() {
			dstAtomNegate := dstAtom.negate().(atomicTerm)
			if allowPath.Dst.isTautology() {
				resAllowPaths = append(resAllowPaths, &SymbolicPath{Src: allowPath.Src, Dst: Conjunction{&dstAtomNegate},
					Conn: netset.AllTransports()})
			} else {
				resAllowPaths = append(resAllowPaths, &SymbolicPath{Src: allowPath.Src, Dst: *allowPath.Dst.copy().add(&dstAtomNegate),
					Conn: netset.AllTransports()})
			}
		}
	}
	return &resAllowPaths
}

// ConvertFWRuleToSymbolicPaths given a rule, converts its src, dst and Conn to SymbolicPaths
func ConvertFWRuleToSymbolicPaths(rule *dfw.FwRule) *SymbolicPaths {
	resSymbolicPaths := SymbolicPaths{}
	tarmAny := Conjunction{tautology{}}
	srcTerms := getAtomicTermsForGroups(rule.SrcGroups)
	dstTerms := getAtomicTermsForGroups(rule.DstGroups)
	switch {
	case rule.IsAllSrcGroups && rule.IsAllDstGroups:
		resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: tarmAny, Dst: tarmAny, Conn: netset.AllTransports()})
	case rule.IsAllSrcGroups:
		for _, dstTerm := range dstTerms {
			resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: tarmAny, Dst: Conjunction{dstTerm},
				Conn: netset.AllTransports()})
		}
	case rule.IsAllDstGroups:
		for _, srcTerm := range srcTerms {
			resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: Conjunction{srcTerm}, Dst: tarmAny,
				Conn: netset.AllTransports()})
		}
	default:
		for _, srcTerm := range srcTerms {
			for _, dstTerm := range dstTerms {
				resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Src: Conjunction{srcTerm},
					Dst: Conjunction{dstTerm}, Conn: netset.AllTransports()})
			}
		}
	}
	return &resSymbolicPaths
}
