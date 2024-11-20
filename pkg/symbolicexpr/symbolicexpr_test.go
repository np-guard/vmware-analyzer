package symbolicexpr

import (
	"fmt"
	"testing"
)

type testTag struct {
	name string
}

func initTestTag(name string) *testTag {
	return &testTag{name: name}
}

func (testT *testTag) Name() string {
	return testT.name
}

func TestSymbolicExpr(t *testing.T) {
	conj1, conj2, conj3, conj4 := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	for i := 1; i <= 10; i++ {
		testTag := initTestTag(fmt.Sprintf("t1-%v", i))
		atomic := &Atomic{label: testTag, toVal: fmt.Sprintf("str1-%v", i), neg: i%2 == 0}
		conj1 = *conj1.add(atomic)
	}
	println("conj1:\n", conj1.string())
	for i := 1; i <= 4; i++ {
		testTag := initTestTag(fmt.Sprintf("t2-%v", i))
		atomic := &Atomic{label: testTag, toVal: fmt.Sprintf("str2-%v", i), neg: i%2 == 0}
		conj2 = *conj2.add(atomic)
	}
	println("conj2:\n", conj2.string())
	for i := 1; i <= 7; i++ {
		testTag := initTestTag(fmt.Sprintf("t3-%v", i))
		atomic := &Atomic{label: testTag, toVal: fmt.Sprintf("str3-%v", i), neg: i%2 == 0}
		conj3 = *conj3.add(atomic)
	}
	println("conj3:\n", conj3.string())
	println("conj4:\n", conj4.string())
	dnf1 := DNFExpr{}
	dnf1 = *dnf1.add(conj1)
	dnf1 = *dnf1.add(conj2)
	dnf1 = *dnf1.add(conj3)
	dnf1 = *dnf1.add(conj4)
	println("dnf1:\n", dnf1.string())
}
