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
		atomicSrc := atomicTerm{label: testTag1, toVal: fmt.Sprintf("str1-%v", i), neg: i%2 == 0}
		testTag2 := initTestTag(fmt.Sprintf("dst-%v", i))
		atomicDst := atomicTerm{label: testTag2, toVal: fmt.Sprintf("str2-%v", i), neg: i%2 == 0}
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

	testSrc := initTestTag(fmt.Sprintf("srcTag"))
	testDst := initTestTag(fmt.Sprintf("srcDst"))
	atomicSrc := atomicTerm{label: testSrc, toVal: fmt.Sprintf("str1")}
	atomicDst := atomicTerm{label: testDst, toVal: fmt.Sprintf("dst1")}
	taut := &tautology{}
	allDsts := simplePath{atomicSrc, taut}
	allSrcs := simplePath{taut, atomicDst}
	fmt.Printf("allSrcs path: %v\nallDsts path: %v\n", allSrcs.string(), allDsts.string())
	require.Equal(t, "* to srcDst = dst1", allSrcs.string(), "allSrcs not as expected")
	require.Equal(t, "srcTag = str1 to *", allDsts.string(), "allDsts not as expected")
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
	require.Equal(t, emptySet, conjEmpty.string(), "empty conjunction not as expected")
}

func TestComputeAllowGivenDenySingleTermEach(t *testing.T) {
	conjSrc1, conjDst1, conjSrc2, conjDst2 := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	testTag1 := initTestTag(fmt.Sprintf("t1"))
	atomic1 := &atomicTerm{label: testTag1, toVal: fmt.Sprintf("str1")}
	conjSrc1 = *conjSrc1.add(atomic1)
	negateAtomic := atomic1.negate().(atomicTerm)
	conjDst1 = *conjDst1.add(&negateAtomic)
	testTag2 := initTestTag(fmt.Sprintf("t2"))
	atomic2 := &atomicTerm{label: testTag2, toVal: fmt.Sprintf("str2")}
	negateAtomic2 := atomic2.negate().(atomicTerm)
	conjSrc2 = *conjSrc2.add(atomic2)
	conjDst2 = *conjDst2.add(&negateAtomic2)
	allowPath := SymbolicPath{conjSrc1, conjDst1}
	denyPath := SymbolicPath{conjSrc2, conjDst2}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.string())
	require.Equal(t, "(t1 = str1 and t2 != str2) to (t1 != str1)\n(t1 = str1) to (t1 = str1 and t2 = str2)",
		allowGivenDeny.string(), "allowGivenDeny single term computation not as expected")
}

func TestComputeAllowGivenDenyThreeTermsEach(t *testing.T) {
	conjAllow, conjDeny := Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		testAllow := initTestTag(fmt.Sprintf("s%v", i))
		atomicAllow := &atomicTerm{label: testAllow, toVal: fmt.Sprintf("str%v", i)}
		conjAllow = *conjAllow.add(atomicAllow)
		testDeny := initTestTag(fmt.Sprintf("s%v`", i))
		atomicDeny := &atomicTerm{label: testDeny, toVal: fmt.Sprintf("str%v`", i)}
		conjDeny = *conjDeny.add(atomicDeny)
	}
	allowPath := SymbolicPath{conjAllow, conjAllow}
	denyPath := SymbolicPath{conjDeny, conjDeny}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.string())
	require.Equal(t,
		"(s1 = str1 and s2 = str2 and s3 = str3 and s1` != str1`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"(s1 = str1 and s2 = str2 and s3 = str3 and s2` != str2`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"(s1 = str1 and s2 = str2 and s3 = str3 and s3` != str3`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"(s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s1` != str1`)\n"+
			"(s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s2` != str2`)\n"+
			"(s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s3` != str3`)",
		allowGivenDeny.string(), "allowGivenDeny three terms computation not as expected")
}

func TestComputeAllowGivenDenyAllowTautology(t *testing.T) {
	conjDeny := Conjunction{}
	for i := 1; i <= 3; i++ {
		testDeny := initTestTag(fmt.Sprintf("s%v`", i))
		atomicDeny := &atomicTerm{label: testDeny, toVal: fmt.Sprintf("str%v`", i)}
		conjDeny = *conjDeny.add(atomicDeny)
	}
	tautologyConj := Conjunction{tautology{}}
	allowPath := SymbolicPath{tautologyConj, tautologyConj}
	denyPath := SymbolicPath{conjDeny, conjDeny}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.string())
	require.Equal(t,
		"(s1` != str1`) to (*)\n(s2` != str2`) to (*)\n(s3` != str3`) to (*)\n(*) to (s1` != str1`)\n"+
			"(*) to (s2` != str2`)\n(*) to (s3` != str3`)", allowGivenDeny.string(),
		"allowGivenDeny allow tautology computation not as expected")
}

func TestComputeAllowGivenDenyDenyTautology(t *testing.T) {
	conjAllow := Conjunction{}
	for i := 1; i <= 3; i++ {
		testAllow := initTestTag(fmt.Sprintf("s%v`", i))
		atomicAllow := &atomicTerm{label: testAllow, toVal: fmt.Sprintf("str%v`", i)}
		conjAllow = *conjAllow.add(atomicAllow)
	}
	tautologyConj := Conjunction{tautology{}}
	allowPath := SymbolicPath{conjAllow, conjAllow}
	denyPath := SymbolicPath{tautologyConj, tautologyConj}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.string())
	require.Equal(t, emptySet, allowGivenDeny.string(),
		"allowGivenDeny deny tautology computation not as expected")
}
