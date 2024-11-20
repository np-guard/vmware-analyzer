package symbolicexpr

import "strings"

func (c *Conjunction) string() string {
	resArray := make([]string, len(*c))
	for i, atomic := range *c {
		resArray[i] = atomic.string()
	}
	return "(" + strings.Join(resArray, " and ") + ")"
}

func (c *Conjunction) add(atomic *Atomic) *Conjunction {
	res := append(*c, atomic)
	return &res
}
