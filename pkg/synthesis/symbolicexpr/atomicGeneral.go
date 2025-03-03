package symbolicexpr

import (
	"slices"
)

// tautology implementation

func (tautology) String() string {
	return "*"
}

func (tautology) name() string {
	return ""
}

func (tautology) negate() atomic {
	return tautology{}
}

func (tautology) isNegation() bool {
	return false
}

func (tautology) IsTautology() bool {
	return true
}

// returns true iff otherAt is negation of
// once we cache the atomic terms, we can just compare pointers
func (tautology) isNegateOf(atomic) bool {
	return false
}
func (tautology) AsSelector() (string, bool) {
	return "", false
}

// tautology is not disjoint to any atomic term
func (tautology) disjoint(atomic, *Hints) bool {
	return false
}

func (tautology) supersetOf(atom atomic, hints *Hints) bool {
	return atom.IsTautology()
}

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

// IsTautology an atomicTerm is a non empty cond on a group, a tag etc and is thus not a tautology
func (atomicTerm) IsTautology() bool {
	return false
}

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
	// in hints list of disjoint groups/tags/.. is given. Actual atomicTerms are disjoint only if both not negated
	if atom.isNegation() || otherAtom.isNegation() {
		return false
	}
	return hints.disjoint(atom.name(), otherAtom.name())
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
