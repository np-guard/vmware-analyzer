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

func (c *Conjunction) add(atom atomic) *Conjunction {
	if c.contains(atom) {
		return c
	}
	res := append(*c, atom)
	return &res
}

func (c *Conjunction) copy() *Conjunction {
	newC := Conjunction{}
	newC = append(newC, *c...)
	return &newC
}

func (c *Conjunction) isTautology() bool {
	if len(*c) == 1 && (*c)[0].IsTautology() {
		return true
	}
	return false
}

// remove redundant terms: tautology or redundant as per hints; the latter is when e.g., a and b are disjoint
// then "a and not b" - b is redundant
func (c *Conjunction) removeRedundant(hints *Hints) Conjunction {
	if len(*c) <= 1 {
		return *c
	}
	newC := Conjunction{}
	redundantRemoved := false
	for _, atom := range *c {
		if !atom.IsTautology() && !atomRedundantInConj(atom, c, hints) {
			newC = append(newC, atom)
		} else {
			redundantRemoved = true
		}
	}
	if len(newC) == 0 && redundantRemoved {
		return Conjunction{tautology{}}
	}
	return newC
}

// atomic atom is a redundant in Conjunction c, if it is a superset of one of c's terms
func atomRedundantInConj(atom atomic, c *Conjunction, hints *Hints) bool {
	if len(*c) == 0 { // nil Conjunction is equiv to tautology
		return false
	}
	for _, otherAtom := range *c {
		if atom.supersetOf(otherAtom, hints) {
			return true
		}
	}
	return false
}

// checks whether the conjunction is empty: either syntactically, or contains an groupAtomicTerm and its negation
// or contains two atoms that are disjoint to each other by hints
func (c *Conjunction) isEmptySet(hints *Hints) bool {
	if len(*c) == 0 {
		return true
	}
	for i, outAtomicTerm := range *c {
		reminder := *c
		reminder = reminder[i+1:]
		for _, inAtomicTerm := range reminder {
			if outAtomicTerm.isNegateOf(inAtomicTerm) || outAtomicTerm.disjoint(inAtomicTerm, hints) {
				return true
			}
		}
	}
	return false
}

// checks whether conjunction other is disjoint to conjunction c
// this is the case if there's a term in c and its contradiction in other
// or if there are two terms that are disjoint to each other by hints
func (c *Conjunction) disjoint(other *Conjunction, hints *Hints) bool {
	if len(*c) == 0 || len(*other) == 0 {
		return false
	}
	if other.isTautology() || c.isTautology() {
		return false
	}
	for _, atomicTerm := range *other {
		if c.contains(atomicTerm.negate()) || c.contradicts(atomicTerm, hints) {
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

func (c *Conjunction) contradicts(atom atomic, hints *Hints) bool {
	for _, atomicTerm := range *c {
		if atomicTerm.disjoint(atom, hints) {
			return true
		}
	}
	return false
}

// Conjunction c is superset of other iff any term in c either exists in other or is a superset of it
func (c *Conjunction) isSuperset(other *Conjunction, hints *Hints) bool {
	if len(*c) == 0 && !other.isTautology() { // nil Conjunction is equiv to tautology
		return false
	}
	for _, atom := range *c {
		if !other.contains(atom) && !atomSupersetOfConj(atom, other, hints) {
			return false
		}
	}
	return true
}

// atomic a is a superset of Conjunction c if it is a subset of any of its terms
func atomSupersetOfConj(atom atomic, c *Conjunction, hints *Hints) bool {
	if len(*c) == 0 { // nil Conjunction is equiv to tautology
		return false
	}
	for _, otherAtom := range *c {
		if !otherAtom.supersetOf(atom, hints) {
			return false
		}
	}
	return true
}
