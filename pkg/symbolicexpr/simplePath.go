package symbolicexpr

import "strings"

func (path *simplePath) string() string {
	return path.src.string() + " -> " + path.dst.string()
}

func (paths *simplePaths) string() string {
	res := make([]string, len(*paths))
	for i, path := range *paths {
		res[i] = path.string()
	}
	return strings.Join(res, "\n")
}
