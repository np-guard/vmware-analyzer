package symbolicexpr

import "strings"

func (path *SymbolicPath) string() string {
	return path.Src.string() + " -> " + path.Dst.string()
}

func (paths *SymbolicPaths) string() string {
	res := make([]string, len(*paths))
	for i, path := range *paths {
		res[i] = path.string()
	}
	return strings.Join(res, "/n")
}
