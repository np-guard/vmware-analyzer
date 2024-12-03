package symbolicexpr

import (
	"fmt"
	"strings"
)

func (path *SymbolicPath) string() string {
	return path.Src.string() + " to " + path.Dst.string()
}

func (paths *SymbolicPaths) string() string {
	if len(*paths) == 0 {
		return emptySet
	}
	res := make([]string, len(*paths))
	for i, path := range *paths {
		res[i] = path.string()
	}
	return strings.Join(res, "\n")
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
				resAllowPaths = append(resAllowPaths, &SymbolicPath{Conjunction{&srcAtomNegate}, allowPath.Dst})
			} else {
				resAllowPaths = append(resAllowPaths, &SymbolicPath{*allowPath.Src.copy().add(&srcAtomNegate), allowPath.Dst})
			}
		}
	}
	for _, dstAtom := range denyPath.Dst {
		if !dstAtom.isTautology() {
			dstAtomNegate := dstAtom.negate().(atomicTerm)
			if allowPath.Dst.isTautology() {
				resAllowPaths = append(resAllowPaths, &SymbolicPath{allowPath.Src, Conjunction{&dstAtomNegate}})
			} else {
				resAllowPaths = append(resAllowPaths, &SymbolicPath{allowPath.Src, *allowPath.Dst.copy().add(&dstAtomNegate)})
			}
		}
	}
	return &resAllowPaths
}

// algorithm described in README of symbolicexpr
// the resulting denys are proceeded with allows in lower priority categories
// Note that here, unlike in the computation of allow given deny, we can't proceed each pass in isolation w.r.t. deny
// ToDo: we assume that srcs (dsts) of passes in the same category are disjoint
func computeDenyGivenDenyHigherPasses(denyPath SymbolicPath, passPaths SymbolicPaths) *SymbolicPaths {
	resSymbolicPaths := SymbolicPaths{}
	// 1. Path(s) in which the src is not in any of the original sources or dst is not in any of the original destinations
	notInSrcOrNotInDstPaths := computeNegateSrcDstPaths(passPaths)
	for _, notSrcOrNotDst := range *notInSrcOrNotInDstPaths {
		denyNotPassSrc := add(&denyPath.Src, &notSrcOrNotDst.Src)
		denyNotPassDst := add(&denyPath.Dst, &notSrcOrNotDst.Dst)
		resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{*denyNotPassSrc, Conjunction{tautology{}}})
		resSymbolicPaths = append(resSymbolicPaths, &SymbolicPath{Conjunction{tautology{}}, *denyNotPassDst})
	}
	// 2. Passes in which the src and the dst are in the original src and dsts, but not the "pass" couples
	return nil
}

// given a set of paths, computes the set of paths representing src not in any of the original sources
// or destination not in any of the original destinations
// used by computeAllowGivenAllowHigherPasses to compute the first component of the result, as described in README
func computeNegateSrcDstPaths(paths SymbolicPaths) *SymbolicPaths {
	// 1. Computes Conjunctions of srcs and Conjunctions of destinations
	srcConjunctions, dstConjunctions := make([]Conjunction, len(paths)), make([]Conjunction, len(paths))
	for i, path := range paths {
		srcConjunctions[i] = path.Src
		dstConjunctions[i] = path.Dst
	}
	// 2. Negates src and dst
	negateSrcConjunctions, negateDstConjunctions := negateConjunctions(srcConjunctions), negateConjunctions(dstConjunctions)
	// 3. Computes all paths in which src is not in any of the original srcs or dst is not in any of the original dsts
	resNegatePaths := SymbolicPaths{}
	for _, src := range negateSrcConjunctions {
		resNegatePaths = append(resNegatePaths, &SymbolicPath{src, Conjunction{tautology{}}})
	}
	for _, dst := range negateDstConjunctions {
		resNegatePaths = append(resNegatePaths, &SymbolicPath{Conjunction{tautology{}}, dst})
	}
	return &resNegatePaths
}
