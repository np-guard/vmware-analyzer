package symbolicexpr

import (
	"strings"
)

const emptySet = "empty set "

func (c *Conjunction) string() string {
	resArray := make([]string, len(*c))
	for i, atomic := range *c {
		resArray[i] = atomic.string()
	}
	if len(resArray) == 0 {
		return emptySet
	}
	return "(" + strings.Join(resArray, " and ") + ")"
}

func (c *Conjunction) add(atomic *atomicTerm) *Conjunction {
	res := append(*c, atomic)
	return &res
}

func (c *Conjunction) copy() *Conjunction {
	newC := Conjunction{}
	newC = append(newC, *c...)
	return &newC
}

func (c *Conjunction) isTautology() bool {
	if len(*c) == 1 && (*c)[0].isTautology() {
		return true
	}
	return false
}

// checks whether the Conjunction is empty: either syntactically, or contains an atomicTerm and its negation
func (c *Conjunction) isEmptySet() bool {
	if len(*c) == 0 {
		return true
	}
	for i, outAtomicTerm := range *c {
		reminder := *c
		reminder = reminder[i+1:]
		for _, inAtomicTerm := range reminder {
			if outAtomicTerm.isNegateOf(inAtomicTerm) {
				return true
			}
		}
	}
	return false
}
