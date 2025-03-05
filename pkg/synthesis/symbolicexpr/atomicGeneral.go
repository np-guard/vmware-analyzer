package symbolicexpr

import (
	"slices"
)

// general atomic functionality

// are two given by name atomicTerms in disjoint list
func (hints *Hints) disjoint(name1, name2 string) bool {
	if name1 == name2 {
		return false
	}
	for _, disjointGroup := range hints.GroupsDisjoint {
		if slices.Contains(disjointGroup, name1) && slices.Contains(disjointGroup, name2) {
			return true
		}
	}
	return false
}

// functions of Atomic with identical impl of all implementing structs

func (atomicTerm atomicTerm) isNegation() bool {
	return atomicTerm.neg
}

// there are several derive classes - groupTerm, atomicTerm, of "atomic" base class
// however, in golang there is no pattern in which the code of the base class can call the derived class methods.
// thus each derive member function calls the common code
//  1. the base class is implemented as an interface
//  2. the receiver of the methods of the base class are given to the method as first argument.
func isNegateOf(atom, otherAtom atomic) bool {
	return atom.String() == otherAtom.negate().String()
}

// returns true iff otherAtom is disjoint to atom as given by hints
// todo: could e.g. groups and tags have the same name????
func disjoint(atom, otherAtom atomic, hints *Hints) bool {
	atomBlock := getBlock(atom)
	otherAtomBlock := getBlock(otherAtom)
	switch {
	case atomBlock != nil && otherAtomBlock != nil:
		return atomBlock.Intersect(otherAtomBlock).IsEmpty()
	case atomBlock != nil || otherAtomBlock != nil:
		return false
	default:
		// in hints list of disjoint groups/tags/.. is given. Actual atomicTerms are disjoint only if both not negated
		if atom.isNegation() || otherAtom.isNegation() {
			return false
		}
		return hints.disjoint(atom.name(), otherAtom.name())
	}
}

// returns true iff atom is supersetOf of otherAtom other as given by hints
// in hints list of disjoint groups/tags/.. is given. Term1 is superset by term2 if they are disjoint and
// term1 is not negated while term2 is
// e.g., given that Slytherin and Hufflepuff are disjoint, group != Hufflepuff is a superset of group = Slytherin
// if in the same Clause, we can rid group != Hufflepuff
func supersetOf(atom, otherAtom atomic, hints *Hints) bool {
	return hints.disjoint(atom.name(), otherAtom.name()) && atom.isNegation() && !otherAtom.isNegation()
}

// return equalSignConst or nonEqualSignConst for atom
func eqSign(atom atomic) string {
	equalSign := equalSignConst
	if atom.isNegation() {
		equalSign = nonEqualSignConst
	}
	return equalSign
}
