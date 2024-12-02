package symbolicexpr

import (
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
// todo: describe alg and implement
func ComputeAllowGivenDenies(allowPaths, denyPaths SymbolicPaths) *SymbolicPaths {
	_, _ = allowPaths, denyPaths
	computeAllowGivenDeny(SymbolicPath{}, SymbolicPath{})
	return nil
}

// algorithm description: https://ibm.ent.box.com/notes/1702367247616 // todo: move to some other place? perhaps git?
func computeAllowGivenDeny(allowPath, denyPath SymbolicPath) *SymbolicPaths {
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