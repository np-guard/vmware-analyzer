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
		atomicSrc := &atomicTerm{label: testTag1, toVal: fmt.Sprintf("str1-%v", i), neg: i%2 == 0}
		testTag2 := initTestTag(fmt.Sprintf("dst-%v", i))
		atomicDst := &atomicTerm{label: testTag2, toVal: fmt.Sprintf("str2-%v", i), neg: i%2 == 0}
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
}

func TestSymbolicPaths(t *testing.T) {
	conjSrc, conjDst, conjEmpty := Conjunction{}, Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		testTag := initTestTag(fmt.Sprintf("t%v", i))
		atomic := &atomicTerm{label: testTag, toVal: fmt.Sprintf("str%v", i)}
		conjSrc = *conjSrc.add(atomic)
		negateAtomic := atomic.negate().(atomicTerm)
		conjDst = *conjDst.add(&negateAtomic)
	}
	conjSymbolicPath := SymbolicPath{conjSrc, conjDst}
	fmt.Printf("\nconjSymbolicPath:\n%v\n", conjSymbolicPath.string())
	require.Equal(t, "(t1 = str1 and t2 = str2 and t3 = str3) to (t1 != str1 and t2 != str2 and t3 != str3)",
		conjSymbolicPath.string(), "conjSymbolicPath not as expected")
	println("conjEmpty", conjEmpty.string())
	require.Equal(t, "", conjEmpty.string(), "empty path not as expected")
}
