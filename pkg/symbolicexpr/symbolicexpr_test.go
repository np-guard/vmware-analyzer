package symbolicexpr

import (
	"fmt"
	"github.com/stretchr/testify/require"
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

func TestSimplePaths(t *testing.T) {
	simplePaths := simplePaths{}
	for i := 1; i <= 5; i++ {
		testTag1 := initTestTag(fmt.Sprintf("src-%v", i))
		atomicSrc := &Atomic{label: testTag1, toVal: fmt.Sprintf("str1-%v", i), neg: i%2 == 0}
		testTag2 := initTestTag(fmt.Sprintf("dst-%v", i))
		atomicDst := &Atomic{label: testTag2, toVal: fmt.Sprintf("str2-%v", i), neg: i%2 == 0}
		simplePaths = append(simplePaths, &simplePath{atomicSrc, atomicDst})
	}
	fmt.Printf("\nsimple paths:\n%v\n", simplePaths.string())
	require.Contains(t, simplePaths.string(), "src-1 = str1-1 to dst-1 = str2-1",
		"simple path0 not as expected")
	require.Contains(t, simplePaths.string(), "src-2 != str1-2 to dst-2 != str2-2",
		"simple path1 not as expected")
	require.Contains(t, simplePaths.string(), "src-4 != str1-4 to dst-4 != str2-4",
		"simple path3 not as expected")
	require.Contains(t, simplePaths.string(), "src-5 = str1-5 to dst-5 = str2-5",
		"simple path4 not as expected")
	fmt.Printf("negate path[0]: %v\n", simplePaths[0].negate().string())
	require.Equal(t, "src-1 != str1-1 to dst-1 != str2-1", simplePaths[0].negate().string(),
		"negate simple path0 not as expected")
	require.Equal(t, "src-5 != str1-5 to dst-5 != str2-5", simplePaths[4].negate().string(),
		"negate simple path4 not as expected")
}

func TestSymbolicPaths(t *testing.T) {
	conjSrc, conjDst, conjEmpty := Conjunction{}, Conjunction{}, Conjunction{}
	simplePaths := simplePaths{}
	for i := 1; i <= 10; i++ {
		testTag1 := initTestTag(fmt.Sprintf("src-%v", i))
		atomicSrc := &Atomic{label: testTag1, toVal: fmt.Sprintf("str1-%v", i), neg: i%2 == 0}
		testTag2 := initTestTag(fmt.Sprintf("dst-%v", i))
		atomicDst := &Atomic{label: testTag2, toVal: fmt.Sprintf("str2-%v", i), neg: i%2 == 0}
		simplePaths = append(simplePaths, &simplePath{atomicSrc, atomicDst})
	}
	fmt.Printf("\nsimple paths:\n%v\n", simplePaths.string())
	src, dst := Conjunction{}, Conjunction{}
	paths := SymbolicPaths{}
	for i := 1; i <= 5; i++ {
		testTag1 := initTestTag(fmt.Sprintf("src-%v", i))
		atomicSrc := &Atomic{label: testTag1, toVal: fmt.Sprintf("str1-%v", i), neg: i%2 == 0}
		src = *src.add(atomicSrc)
		testTag2 := initTestTag(fmt.Sprintf("dst-%v", i))
		atomicDst := &Atomic{label: testTag2, toVal: fmt.Sprintf("str2-%v", i), neg: i%2 == 0}
		dst = *dst.add(atomicDst)
		path := SymbolicPath{src, dst}
		paths = append(paths, &path)
	}
	fmt.Printf("\npaths:\n%v\n", paths.string())
	fmt.Printf("\npath[0]:\n%v\n", paths[0].string())
	fmt.Printf("\nnegate(path[0]):\n%v\n", paths[0].negate().string())
	for i := 1; i <= 4; i++ {
		testTag := initTestTag(fmt.Sprintf("t%v", i))
		atomic := &Atomic{label: testTag, toVal: fmt.Sprintf("str%v", i)}
		conjSrc = *conjSrc.add(atomic)
		conjDst = *conjDst.add(atomic.negate())
	}
	conjSymbolicPath := SymbolicPath{conjSrc, conjDst}
	fmt.Printf("conjSrc: %v to conjDst : %v\n", conjSrc.string(), conjDst.string())
	fmt.Printf("\nconjSymbolicPath:\n%v", conjSymbolicPath.string())
	fmt.Printf("\nnegate conjSymbolicPath:\n%v", conjSymbolicPath.negate().string())
	println("conjEmpty", conjEmpty.string())
}
