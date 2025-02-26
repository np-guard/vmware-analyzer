package common

import (
	"maps"
	"slices"
)

func SliceCountFunc[v any](s []v, f func(v) bool) int {
	c := 0
	for _, e := range s {
		if f(e) {
			c++
		}
	}
	return c
}

func SliceCompact[A comparable](s []A) []A {
	set := map[A]bool{}
	for _, e := range s {
		set[e] = true
	}
	return slices.Collect(maps.Keys(set))
}
