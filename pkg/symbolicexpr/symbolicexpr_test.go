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
	conj1 := Conjunction{}
	for i := 1; i <= 10; i++ {
		testTag := initTestTag(fmt.Sprintf("tag%v", i))
		atomic := &Atomic{label: testTag, toVal: fmt.Sprintf("equalTo%v", i), neg: i%2 == 0}
		conj1 = *conj1.add(atomic)
	}
	println(conj1.string())
}
