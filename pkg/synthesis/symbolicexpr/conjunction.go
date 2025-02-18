package symbolicexpr

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
)

const emptySet = "empty set "

func (c *Conjunction) String() string {
	if len(*c) == 0 {
		return emptySet
	}
	return "(" + common.JoinStringifiedSlice(*c, " and ") + ")"
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
		if atomicTerm.String() == (atom).String() {
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

// Conjunction c is superset of other if either:
// any resource satisfying other also satisfies c,
// this is the case if any term in c either exists in other or is a subset of it, or
// c is tautology
func (c *Conjunction) isSuperset(other *Conjunction, hints *Hints) bool {
	if c.isTautology() || len(*c) == 0 { // tautology superset of everything;  nil Conjunction is equiv to tautology
		return true
	}
	if other.isTautology() { // tautology is a subset only of tautology
		return false
	}
	for _, atom := range *c {
		if !other.contains(atom) && !conjSupersetOfAtom(other, atom, hints) {
			return false
		}
	}
	return true
}

// Conjunction c is a superset of atomic atom if any resource satisfying atom also satisfies c
// this is the case if each of c's term is a superset of atom
// e.g., given that Slytherin and Hufflepuff are disjoint, group != Hufflepuff is a superset of group = Slytherin
func conjSupersetOfAtom(c *Conjunction, atom atomic, hints *Hints) bool {
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
