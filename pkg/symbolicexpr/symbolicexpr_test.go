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
	atomics := Atomics{}
	for i := 1; i <= 10; i++ {
		testTag := initTestTag(fmt.Sprintf("tag%v", i))
		atomic := &Atomic{label: testTag, toVal: fmt.Sprintf("equalTo%v", i), neg: i%2 == 0}
		atomics[atomic.string()] = atomic
	}
	for key, myAtomic := range atomics {
		fmt.Printf("key: %v, negate: %s\n", key, myAtomic.negate().string())
	}
}
