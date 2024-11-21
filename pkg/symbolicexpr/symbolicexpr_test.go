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
	conj, conjEmpty := Conjunction{}, Conjunction{}
	paths := SymbolicPaths{}
	for i := 1; i <= 5; i++ {
		testTag1 := initTestTag(fmt.Sprintf("src-%v", i))
		atomicSrc := &Atomic{label: testTag1, toVal: fmt.Sprintf("str1-%v", i), neg: i%2 == 0}
		src := Conjunction{atomicSrc}
		testTag2 := initTestTag(fmt.Sprintf("dst-%v", i))
		atomicDst := &Atomic{label: testTag2, toVal: fmt.Sprintf("str2-%v", i), neg: i%2 == 0}
		dst := Conjunction{atomicDst}
		path := SymbolicPath{src, dst}
		simpPath := simplePath{atomicSrc, atomicDst}
		fmt.Printf("path%v: %v\n", i, path.string())
		fmt.Printf("simplePath: %v\n", simpPath.string())
	}
	println("\npaths:\n", paths.string())
	for i := 1; i <= 7; i++ {
		testTag := initTestTag(fmt.Sprintf("t-%v", i))
		atomic := &Atomic{label: testTag, toVal: fmt.Sprintf("str3-%v", i), neg: i%2 == 0}
		conj = *conj.add(atomic)
	}
	println("conj3:\n", conj.string())
	println("conj4:\n", conjEmpty.string())
}
