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
	if c.contains(atomic) {
		return c
	}
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

func (c *Conjunction) removeTautology() Conjunction {
	if len(*c) <= 1 {
		return *c
	}
	newC := Conjunction{}
	for _, atom := range *c {
		if !atom.isTautology() {
			newC = append(newC, atom)
		}
	}
	return newC
}

// checks whether the conjunction is empty: either syntactically, or contains an atomicTerm and its negation
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

// checks whether conjunction other is implies by conjunction c
func (c *Conjunction) implies(other *Conjunction) bool {
	if other.isTautology() {
		return true
	}
	if len(*c) == 0 || len(*other) == 0 {
		return false
	}
	for _, atomicTerm := range *other {
		if !c.contains(atomicTerm) {
			return false
		}
	}
	return true
}

// checks whether conjunction other is disjoint to conjunction c
// this is the case if there's a term in c and its contradiction in other
// we will later add hints
func (c *Conjunction) disjoint(other *Conjunction) bool {
	if len(*c) == 0 || len(*other) == 0 {
		return false
	}
	if other.isTautology() || c.isTautology() {
		return false
	}
	for _, atomicTerm := range *other {
		if c.contains(atomicTerm.negate()) {
			return true
		}
	}
	return false
}

func (c *Conjunction) contains(atom atomic) bool {
	for _, atomicTerm := range *c {
		if atomicTerm.string() == (atom).string() {
			return true
		}
	}
	return false
}
