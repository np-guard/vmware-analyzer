package symbolicexpr

import "strings"

func (c *Conjunction) string() string {
	resArray := make([]string, len(*c))
	for i, atomic := range *c {
		resArray[i] = atomic.string()
	}
	if len(resArray) == 0 {
		return ""
	}
	return "(" + strings.Join(resArray, " and ") + ")"
}

func (c *Conjunction) add(atomic *atomicTerm) *Conjunction {
	res := append(*c, atomic)
	return &res
}

func (c *Conjunction) copy() *Conjunction {
	newC := Conjunction{}
	for _, v := range *c {
		newC = append(newC, v)
	}
	return &newC
}

func (c *Conjunction) isTautology() bool {
	if len(*c) == 1 && (*c)[0].isTautology() {
		return true
	}
	return false
}
