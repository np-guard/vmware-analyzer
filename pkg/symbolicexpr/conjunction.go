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

// given ORed Conjunctions, returns their negation, also as ORed Conjunctions
// e.g.: for [a, b, c] returns [not a and not b and not c]
// for [a1 and a2, b1 and b2, c1 and c2] returns
// [not a1 and not b1 and not c1,
//
//	not a1 and not b1 and not c2,
//	not a1 and not b2 and not c1,
//	not a1 and not b2 and not c2,
//	not a2 and not b1 and not c1,
//	not a2 and not b1 and not c2,
//	not a2 and not b2 and not c1,
//	not a2 and not b2 and not c2]
func negateConjunctions(conjunctions []Conjunction) []Conjunction {
	var res, resWithoutCurrentCon []Conjunction
	resWithoutCurrentCon = []Conjunction{}
	for _, conj := range conjunctions {
		res = []Conjunction{}
		for _, literal := range conj {
			if len(resWithoutCurrentCon) == 0 {
				res = append(res, Conjunction{literal.negate()})
			} else {
				newConj := Conjunction{}
				for _, withoutCurrentItem := range resWithoutCurrentCon {
					newConj = append(append(*withoutCurrentItem.copy(), literal.negate()))
					res = append(res, newConj)
				}
			}
		}
		resWithoutCurrentCon = res
	}
	return res
}

func strConjunctions(conjunctions []Conjunction) string {
	strArray := make([]string, len(conjunctions))
	for i, conj := range conjunctions {
		strArray[i] = conj.string()
	}
	return strings.Join(strArray, " or\n")
}
