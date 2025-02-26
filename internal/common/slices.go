package common

func SliceCountFunc[v any](s []v, f func(v) bool) int {
	c := 0
	for _, e := range s {
		if f(e) {
			c++
		}
	}
	return c
}
