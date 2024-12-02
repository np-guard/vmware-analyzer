package symbolicexpr

import "strings"

func (path *simplePath) string() string {
	return path.src.string() + " to " + path.dst.string()
}

func (paths *simplePaths) string() string {
	if len(*paths) == 0 {
		return ""
	}
	res := make([]string, len(*paths))
	for i, path := range *paths {
		res[i] = path.string()
	}
	return strings.Join(res, "\n")
}
