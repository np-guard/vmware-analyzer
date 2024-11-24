package symbolicexpr

import (
	"strings"
)

func (path *SymbolicPath) string() string {
	return path.Src.string() + " to " + path.Dst.string()
}

func (paths *SymbolicPaths) string() string {
	res := make([]string, len(*paths))
	for i, path := range *paths {
		res[i] = path.string()
	}
	return strings.Join(res, "\n")
}

// ComputeAllowGivenDenies converts a set of symbolic allow and deny paths (given as type SymbolicPaths)
// the resulting allow paths in SymbolicPaths
// The motivation here is to unroll allow rule given higher priority deny rule
// todo: describe alg
func ComputeAllowGivenDenies(allowPaths, denyPaths SymbolicPaths) *SymbolicPaths {
	return nil
}

// todo: describe alg
func computeAllowGivenDeny(allowPath SymbolicPath, denyPath SymbolicPath) *SymbolicPaths {
	//resAllowPaths := make([]*SymbolicPath, len(allowPaths)*(len(denyPath.Src)+len(denyPath.Dst))) // todo uncomment
	resAllowPaths := SymbolicPaths{}
	// in case deny path is open from both ends - empty set of allow paths, as will be the result
	// assumption: if more than one term, then non is tautology
	for _, srcAtom := range denyPath.Src {
		switch srcAtom.(type) {
		case atomicTerm:
			var newSrc Conjunction
			copy(newSrc, allowPath.Src)
			newSrc = append(newSrc, srcAtom.negate())
			newPath := &SymbolicPath{newSrc, allowPath.Dst}
			resAllowPaths = append(resAllowPaths, newPath)
		}
	}
	for _, dstAtom := range denyPath.Dst {
		switch dstAtom.(type) {
		case atomicTerm:
			var newDst Conjunction
			copy(newDst, allowPath.Src)
			newDst = append(newDst, dstAtom.negate())
			newPath := &SymbolicPath{allowPath.Src, newDst}
			resAllowPaths = append(resAllowPaths, newPath)
		}
	}
	return &resAllowPaths
}
