package symbolicexpr

import "strings"

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

func ComputeAllowGivenDeny(allowPaths SymbolicPaths, denyPath SymbolicPath) *SymbolicPaths {
	return nil
}
