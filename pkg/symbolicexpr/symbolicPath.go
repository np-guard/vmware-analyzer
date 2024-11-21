package symbolicexpr

import "strings"

func (path *SymbolicPath) string() string {
	return path.Src.string() + " -> " + path.Dst.string()
}

// negate a symbolic path to a set of simple paths
func (path *SymbolicPath) negate() *simplePaths {
	res := simplePaths{}
	for _, srcLiteral := range path.Src {
		for _, dstLiteral := range path.Dst {
			res = append(res, &simplePath{src: srcLiteral.negate(), dst: dstLiteral.negate()})
		}
	}
	return &res
}

func (paths *SymbolicPaths) string() string {
	res := make([]string, len(*paths))
	for i, path := range *paths {
		res[i] = path.string()
	}
	return strings.Join(res, "\n")
}
