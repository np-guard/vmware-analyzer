package symbolicexpr

import (
	"slices"
)

// tautology implementation

func (tautology) string() string {
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

// there are several derive classes - groupTerm, atomicTerm, of "atomic" base class
// however, in golang there is no pattern in which the code of the base class can call the derived class methods.
// thus each derive member function calls the common code
//  1. the base class is implemented as an interface
//  2. the receiver of the methods of the base class are given to the method as first argument.
func isNegateOf(atom, otherAtom atomic) bool {
	return atom.string() == otherAtom.negate().string()
}
