package synthesis

// operators on RuleVMs to be used in synthesis

// union of two RulesVMs
// Not optimized. That is, the result of:
// [{m1} -> {m2}] union [{m1} -> {m3}] is
// [{m1} -> {m2}, {m1}->{m3}]
// and not [{m1, m2} -> {m3}]
func (thisVMs *RuleVMs) union(otherVMs *RuleVMs) *RuleVMs {
	return nil // todo: implement
}

// subtraction of one RuleVMs from another
// Result kept as concise as possible without optimazing. Namely:
// [{m1, m2, m3} -> {m4, m5}, {m6} -> {m5}] minus [{m1} -> {m5}] is
// [{m2, m3} -> {m4}, {m1} -> {m5}, {m6} -> {m5}]
// and not [{m2, m3} -> {m4}, {m1, m6} -> {m5}
func (thisVMs *RuleVMs) subtract(otherVMs *RuleVMs) *RuleVMs {
	return nil // todo: implement
}

// intersection of two RuleVMs
// Result kept as concise as possible without optimazing, as in subtract
func (thisVMs *RuleVMs) intersection(otherVMs *RuleVMs) *RuleVMs {
	return nil // todo: implement
}

// optimize RuleVMs representation, by grouping where possible.
// E.g. [{m1} -> {m3}, {m1} -> {m4}, {m2} -> {m3}, {m2} -> {m4}, {m5} -> {m6}] is
//
//	[{m1, m2} -> {m3, m4}, {m5} -> {m6}]
//
// note: differentiating between vms that form a group to those that are not is left to the actual synthesis
func (thisVMs *RuleVMs) group() *RuleVMs {
	return nil // todo: implement
}
