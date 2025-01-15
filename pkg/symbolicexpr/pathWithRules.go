package symbolicexpr

import (
	"fmt"
	"strings"
)

func NewPathsWithRules(paths *SymbolicPaths) *PathsWithRules {
	if len(*paths) == 0 {
		return &PathsWithRules{}
	}
	var newPathsRules PathsWithRules = make([]PathWithRules, len(*paths))
	for i, path := range *paths {
		newPathsRules[i] = PathWithRules{path: path, rules: nil}
	}
	return &newPathsRules
}

func (pathsWithRules *PathsWithRules) getPaths() SymbolicPaths {
	resPaths := make([]*SymbolicPath, len(*pathsWithRules))
	for i, pathWithRules := range *pathsWithRules {
		resPaths[i] = pathWithRules.path
	}
	return resPaths
}

func (pathsWithRules *PathsWithRules) String() string {
	if pathsWithRules == nil {
		return ""
	}
	res := make([]string, len(*pathsWithRules))
	for i, pathWithRules := range *pathsWithRules {
		res[i] = fmt.Sprintf("path %v was effected by the following rules:\n", pathWithRules.path.Src)
		for _, rule := range pathWithRules.rules {
			res[i] += fmt.Sprintf("\t%v\n", rule.String())
		}
	}
	return strings.Join(res, "\n")
}
