package symbolicexpr

// internalIPTerm represents VMs of a given internal address which is not a segment

//
//func (internalIP internalIPTerm) String() string {
//	return "VMs with IP " + internalIP.name()
//}
//
//func (internalIPTerm) AsSelector() (string, bool) {
//	return toImplement, false
//}
//
//func NewGroupInternalIPTerm(group *collector.Group) *internalIPTerm {
//	return &internalIPTerm{abstractGroupTerm: abstractGroupTerm{group: group}}
//}
//
//// negate not defined on an groupAtomicTerm expression
//func (internalIPTerm) negate() atomic {
//	return nil
//}
//
//// returns true iff otherAtom is negation of internalIP
//func (internalIP internalIPTerm) isNegateOf(otherAtom atomic) bool {
//	return isNegateOf(internalIP, otherAtom)
//}
//
//// returns true iff otherAtom is disjoint to internalIP as given by hints
//func (internalIP internalIPTerm) disjoint(otherAtom atomic, hints *Hints) bool {
//	if otherAtom.GetBlock() != nil {
//		return true // otherAtom is an IPBlock; external IP block is disjoint to group terms referring to VMs
//	}
//	return disjoint(internalIP, otherAtom, hints)
//}
//
//// returns true iff internalIP is superset of otherAtom as given by hints
//func (internalIP internalIPTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
//	return supersetOf(internalIP, otherAtom, hints)
//}
