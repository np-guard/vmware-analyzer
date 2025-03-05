package symbolicexpr

// contradiction implementation; contradiction is the negation of tautology

func (contradiction) String() string {
	return "empty set"
}

func (contradiction) name() string {
	return ""
}

func (contradiction) negate() atomic {
	return tautology{}
}

func (contradiction) isNegation() bool {
	return false
}

func (contradiction) IsTautology() bool {
	return false
}

func (contradiction) IsContradiction() bool {
	return true
}

// returns true iff otherAt is negation of
// once we cache the atomic terms, we can just compare pointers
func (contradiction) isNegateOf(atom atomic) bool {
	return atom.IsTautology()
}
func (contradiction) AsSelector() (string, bool) {
	return "", false
}

// contradiction is disjoint to any atomic term
func (contradiction) disjoint(atomic, *Hints) bool {
	return true
}

func (contradiction) supersetOf(atom atomic, hints *Hints) bool {
	return false
}
