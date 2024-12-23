package symbolicexpr

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netset"
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

func TestSymbolicPaths(t *testing.T) {
	conjSrc, conjDst, conjEmpty := Conjunction{}, Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		testTag := initTestTag(fmt.Sprintf("t%v", i))
		atomic := &atomicTerm{property: testTag, toVal: fmt.Sprintf("str%v", i)}
		conjSrc = *conjSrc.add(atomic)
		negateAtomic := atomic.negate().(atomicTerm)
		conjDst = *conjDst.add(&negateAtomic)
	}
	conjSymbolicPath := SymbolicPath{Src: conjSrc, Dst: conjDst, Conn: netset.AllTCPTransport()}
	fmt.Printf("\nconjSymbolicPath:\n%v\n", conjSymbolicPath.string())
	require.Equal(t, "TCP from (t1 = str1 and t2 = str2 and t3 = str3) to (t1 != str1 and t2 != str2 and t3 != str3)",
		conjSymbolicPath.string(), "conjSymbolicPath not as expected")
	println("conjEmpty", conjEmpty.string())
	require.Equal(t, emptySet, conjEmpty.string(), "empty conjunction not as expected")
}

// Input:
// allow symbolic path:
// src: (s1 = str1) dst: (d1 = str1) All Connection
// deny symbolic path:
// src: (s2 = str2) dst: (d2 = str2) UDP
// Output allow paths:
// src: (s1 = str1 and s2 != str2) dst (d1 = str1) All connection
// src: (s1 = str1) dst: (d1 = str1 and d2 != str2) All connection
// src: (s1 = str1) dst: (d1 = str1) ICMP, TCP
// allow symbolic paths:
func TestComputeAllowGivenDenySingleTermEach1(t *testing.T) {
	conjSrc1, conjDst1, conjSrc2, conjDst2 := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	testSrc1 := initTestTag("s1")
	atomic1 := &atomicTerm{property: testSrc1, toVal: "str1"}
	conjSrc1 = *conjSrc1.add(atomic1)
	testDst1 := initTestTag("d1")
	atomicDst1 := &atomicTerm{property: testDst1, toVal: "str1"}
	conjDst1 = *conjDst1.add(atomicDst1)
	testSrc2 := initTestTag("s2")
	atomic2 := &atomicTerm{property: testSrc2, toVal: "str2"}
	conjSrc2 = *conjSrc2.add(atomic2)
	testDst2 := initTestTag("d2")
	atomicDst2 := &atomicTerm{property: testDst2, toVal: "str2"}
	conjDst2 = *conjDst2.add(atomicDst2)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjSrc2, Dst: conjDst2, Conn: netset.AllUDPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t, "All Connections from (s1 = str1 and s2 != str2) to (d1 = str1)\n"+
		"All Connections from (s1 = str1) to (d1 = str1 and d2 != str2)\n"+
		"ICMP,TCP from (s1 = str1) to (d1 = str1)",
		allowGivenDeny.String(), "allowGivenDeny single term computation not as expected")
}

func TestComputeAllowGivenDenySingleTermEach2(t *testing.T) {
	conjSrc1, conjDst1, conjSrc2, conjDst2 := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	testSrc1 := initTestTag("s1")
	atomic1 := &atomicTerm{property: testSrc1, toVal: "str1"}
	conjSrc1 = *conjSrc1.add(atomic1)
	testDst1 := initTestTag("d1")
	atomicDst1 := &atomicTerm{property: testDst1, toVal: "str1"}
	conjDst1 = *conjDst1.add(atomicDst1)
	testSrc2 := initTestTag("s2")
	atomic2 := &atomicTerm{property: testSrc2, toVal: "str2"}
	conjSrc2 = *conjSrc2.add(atomic2)
	testDst2 := initTestTag("d2")
	atomicDst2 := &atomicTerm{property: testDst2, toVal: "str2"}
	conjDst2 = *conjDst2.add(atomicDst2)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllUDPTransport()}
	denyPath := SymbolicPath{Src: conjSrc2, Dst: conjDst2, Conn: netset.AllTCPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	// computeAllowGivenAllowHigherDeny not optimized
	require.Equal(t, "UDP from (s1 = str1 and s2 != str2) to (d1 = str1)\n"+
		"UDP from (s1 = str1) to (d1 = str1 and d2 != str2)\nUDP from (s1 = str1) to (d1 = str1)",
		allowGivenDeny.String(), "allowGivenDeny single term computation not as expected")
	// ComputeAllowGivenDenies optimize
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath})
	fmt.Printf("allowGivenDenyPaths is %v\n", allowGivenDenyPaths.String())
	require.Equal(t, "UDP from (s1 = str1) to (d1 = str1)", allowGivenDenyPaths.String(),
		"ComputeAllowGivenDenies does not work as expected")

}

// Input:
// allow symbolic path:
// (s1 = str1 and s2 = str2 and s3 = str3)  dst: (s1 = str1 and s2 = str2 and s3 = str3) conn TCP
// deny symbolic path:
// src: (s1` = str1` and s2` = str2` and s3` = str3`) dst: (s1` = str1` and s2` = str2` and s3` = str3`) conn ALL
// Output allow paths:
// src: (s1 = str1 and s2 = str2 and s3 = str3 and s1` != str1`) dst: (s1 = str1 and s2 = str2 and s3 = str3)
// src: (s1 = str1 and s2 = str2 and s3 = str3 and s2` != str2`) dst: (s1 = str1 and s2 = str2 and s3 = str3)
// src: (s1 = str1 and s2 = str2 and s3 = str3 and s3` != str3`) dst: (s1 = str1 and s2 = str2 and s3 = str3)
// src: (s1 = str1 and s2 = str2 and s3 = str3) dst: (s1 = str1 and s2 = str2 and s3 = str3 and s1` != str1`)
// src: (s1 = str1 and s2 = str2 and s3 = str3) dst: (s1 = str1 and s2 = str2 and s3 = str3 and s2` != str2`)
// src: (s1 = str1 and s2 = str2 and s3 = str3) dst: (s1 = str1 and s2 = str2 and s3 = str3 and s3` != str3`)
func TestComputeAllowGivenDenyThreeTermsEach(t *testing.T) {
	conjAllow, conjDeny := Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		testAllow := initTestTag(fmt.Sprintf("s%v", i))
		atomicAllow := &atomicTerm{property: testAllow, toVal: fmt.Sprintf("str%v", i)}
		conjAllow = *conjAllow.add(atomicAllow)
		testDeny := initTestTag(fmt.Sprintf("s%v`", i))
		atomicDeny := &atomicTerm{property: testDeny, toVal: fmt.Sprintf("str%v`", i)}
		conjDeny = *conjDeny.add(atomicDeny)
	}
	allowPath := SymbolicPath{Src: conjAllow, Dst: conjAllow, Conn: netset.AllTCPTransport()}
	denyPath := SymbolicPath{Src: conjDeny, Dst: conjDeny, Conn: netset.AllTransports()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t,
		"TCP from (s1 = str1 and s2 = str2 and s3 = str3 and s1` != str1`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3 and s2` != str2`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3 and s3` != str3`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s1` != str1`)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s2` != str2`)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s3` != str3`)",
		allowGivenDeny.String(), "allowGivenDeny three terms computation not as expected")
}

// todo: got here in enriching tests with non trivial connections. Make connection non-trivial when optimization
//
//	of removing redundant path is added
//
// Input:
// allow symbolic path:
// src: src: (*) dst: (*)
// deny symbolic path:
// src: src: (s1` = str1` and s2` = str2` and s3` = str3`) dst: (s1` = str1` and s2` = str2` and s3` = str3`)
// Output allow paths:
// src: (s1` != str1`) dst: (*)
// src: (s2` != str2`) dst: (*)
// src: (s3` != str3`) dst: (*)
// src: (*) dst: (s1` != str1`)
// src: (*) dst: (s2` != str2`)
// src: (*) dst: (s3` != str3`)
func TestComputeAllowGivenDenyAllowTautology(t *testing.T) {
	conjDeny := Conjunction{}
	for i := 1; i <= 3; i++ {
		testDeny := initTestTag(fmt.Sprintf("s%v`", i))
		atomicDeny := &atomicTerm{property: testDeny, toVal: fmt.Sprintf("str%v`", i)}
		conjDeny = *conjDeny.add(atomicDeny)
	}
	tautologyConj := Conjunction{tautology{}}
	allowPath := SymbolicPath{Src: tautologyConj, Dst: tautologyConj, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjDeny, Dst: conjDeny, Conn: netset.AllTransports()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t,
		"All Connections from (s1` != str1`) to (*)\nAll Connections from (s2` != str2`) to (*)\n"+
			"All Connections from (s3` != str3`) to (*)\nAll Connections from (*) to (s1` != str1`)\n"+
			"All Connections from (*) to (s2` != str2`)\nAll Connections from (*) to (s3` != str3`)", allowGivenDeny.String(),
		"allowGivenDeny allow tautology computation not as expected")
}

// Input:
// allow symbolic path:
// src: (s1` = str1` and s2` = str2` and s3` = str3`) dst: (s1` = str1` and s2` = str2` and s3` = str3`)
// deny symbolic path:
// src: * dst: *
// Output allow paths: empty
func TestComputeAllowGivenDenyDenyTautology(t *testing.T) {
	conjAllow := Conjunction{}
	for i := 1; i <= 3; i++ {
		testAllow := initTestTag(fmt.Sprintf("s%v`", i))
		atomicAllow := &atomicTerm{property: testAllow, toVal: fmt.Sprintf("str%v`", i)}
		conjAllow = *conjAllow.add(atomicAllow)
	}
	fmt.Printf("conjAllow is %v\nisEmptySet%v\n\n", conjAllow.string(), conjAllow.isEmptySet())
	tautologyConj := Conjunction{tautology{}}
	allowPath := SymbolicPath{Src: conjAllow, Dst: conjAllow, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: tautologyConj, Dst: tautologyConj, Conn: netset.AllTransports()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.string(), denyPath.string())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath)
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t, emptySet, allowGivenDeny.String(),
		"allowGivenDeny deny tautology computation not as expected")
}

// Input:
// allow symbolic path:
// src: (tag = t0) dst: (tag = t1)
// src: (tag = t2) dst: (tag = t3)
// deny symbolic path:
// src: (segment = s0) dst: (segment = s1)
// src: (segment = s2) dst: (segment = s3)
// src: (segment = s4) dst: (segment = s5)
// Output allow paths:
// src: (tag = t0 and segment != s0 and segment != s2 and segment != s4) dst: (tag = t1)
// src: (tag = t0 and segment != s0 and segment != s2) dst: (tag = t1 and segment != s5)
// src: (tag = t0 and segment != s0 and segment != s4) dst: (tag = t1 and segment != s3)
// src: (tag = t0 and segment != s0) dst: (tag = t1 and segment != s3 and segment != s5)
// src: (tag = t0 and segment != s2 and segment != s4) dst: (tag = t1 and segment != s1)
// src: (tag = t0 and segment != s2) dst: (tag = t1 and segment != s1 and segment != s5)
// src: (tag = t0 and segment != s4) dst: (tag = t1 and segment != s1 and segment != s3)
// src: (tag = t0) dst: (tag = t1 and segment != s1 and segment != s3 and segment != s5)
// src: (tag = t2 and segment != s0 and segment != s2 and segment != s4) dst: (tag = t3)
// src: (tag = t2 and segment != s0 and segment != s2) dst: (tag = t3 and segment != s5)
// src: (tag = t2 and segment != s0 and segment != s4) dst: (tag = t3 and segment != s3)
// src: (tag = t2 and segment != s0) dst: (tag = t3 and segment != s3 and segment != s5)
// src: (tag = t2 and segment != s2 and segment != s4) dst: (tag = t3 and segment != s1)
// src: (tag = t2 and segment != s2) dst: (tag = t3 and segment != s1 and segment != s5)
// src: (tag = t2 and segment != s4) dst: (tag = t3 and segment != s1 and segment != s3)
// src: (tag = t2) dst: (tag = t3 and segment != s1 and segment != s3 and segment != s5)
func TestComputeAllowGivenDenies(t *testing.T) {
	allowPaths, denyPaths := SymbolicPaths{}, SymbolicPaths{}
	testTag := initTestTag("tag")
	testSegment := initTestTag("segment")
	for i := 0; i < 3; i++ {
		if i < 2 {
			atomicAllowSrc := &atomicTerm{property: testTag, toVal: fmt.Sprintf("t%v", 2*i)}
			atomicAllowDst := &atomicTerm{property: testTag, toVal: fmt.Sprintf("t%v", 2*i+1)}
			conjAllowSrc := Conjunction{atomicAllowSrc}
			conjAllowDst := Conjunction{atomicAllowDst}
			allowPaths = append(allowPaths, &SymbolicPath{Src: conjAllowSrc, Dst: conjAllowDst, Conn: netset.AllTransports()})
		}
		atomicDenySrc := &atomicTerm{property: testSegment, toVal: fmt.Sprintf("s%v", 2*i)}
		atomicDenyDst := &atomicTerm{property: testSegment, toVal: fmt.Sprintf("s%v", 2*i+1)}
		conjDenySrc := Conjunction{atomicDenySrc}
		conjDenyDst := Conjunction{atomicDenyDst}
		denyPaths = append(denyPaths, &SymbolicPath{Src: conjDenySrc, Dst: conjDenyDst, Conn: netset.AllTransports()})
	}
	fmt.Printf("allowPaths:\n%v\ndenyPaths:\n%v\n", allowPaths.String(), denyPaths.String())
	res := ComputeAllowGivenDenies(&allowPaths, &denyPaths)
	fmt.Printf("ComputeAllowGivenDenies:\n%v\n", res.String())
	require.Equal(t,
		"All Connections from (tag = t0 and segment != s0 and segment != s2 and segment != s4) to (tag = t1)\n"+
			"All Connections from (tag = t0 and segment != s0 and segment != s2) to (tag = t1 and segment != s5)\n"+
			"All Connections from (tag = t0 and segment != s0 and segment != s4) to (tag = t1 and segment != s3)\n"+
			"All Connections from (tag = t0 and segment != s0) to (tag = t1 and segment != s3 and segment != s5)\n"+
			"All Connections from (tag = t0 and segment != s2 and segment != s4) to (tag = t1 and segment != s1)\n"+
			"All Connections from (tag = t0 and segment != s2) to (tag = t1 and segment != s1 and segment != s5)\n"+
			"All Connections from (tag = t0 and segment != s4) to (tag = t1 and segment != s1 and segment != s3)\n"+
			"All Connections from (tag = t0) to (tag = t1 and segment != s1 and segment != s3 and segment != s5)\n"+
			"All Connections from (tag = t2 and segment != s0 and segment != s2 and segment != s4) to (tag = t3)\n"+
			"All Connections from (tag = t2 and segment != s0 and segment != s2) to (tag = t3 and segment != s5)\n"+
			"All Connections from (tag = t2 and segment != s0 and segment != s4) to (tag = t3 and segment != s3)\n"+
			"All Connections from (tag = t2 and segment != s0) to (tag = t3 and segment != s3 and segment != s5)\n"+
			"All Connections from (tag = t2 and segment != s2 and segment != s4) to (tag = t3 and segment != s1)\n"+
			"All Connections from (tag = t2 and segment != s2) to (tag = t3 and segment != s1 and segment != s5)\n"+
			"All Connections from (tag = t2 and segment != s4) to (tag = t3 and segment != s1 and segment != s3)\n"+
			"All Connections from (tag = t2) to (tag = t3 and segment != s1 and segment != s3 and segment != s5)",
		ComputeAllowGivenDenies(&allowPaths, &denyPaths).String(),
		"ComputeAllowGivenDenies computation not as expected")
}

// Input:
// allow symbolic path:
// s1 = str1 to *
// deny symbolic path:
// (s1 = str1) to (d1 = str1)
// Output allow paths: (s1 = str1) to (d1 != str1)
func TestAllowDenyOptimizeEmptyPath(t *testing.T) {
	conjSrc1, conjDst1 := Conjunction{}, Conjunction{}
	testSrc1 := initTestTag("s1")
	atomic1 := &atomicTerm{property: testSrc1, toVal: "str1"}
	conjSrc1 = *conjSrc1.add(atomic1)
	testDst1 := initTestTag("d1")
	atomicDst1 := &atomicTerm{property: testDst1, toVal: "str1"}
	conjDst1 = *conjDst1.add(atomicDst1)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: Conjunction{tautology{}}, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTransports()}
	allowWithDeny := ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath})
	fmt.Printf("allow path: %v with higher priority deny path:%v is:\n%v\n\n",
		allowPath.string(), denyPath.string(), allowWithDeny.String())
	require.Equal(t, "All Connections from (s1 = str1) to (d1 != str1)", allowWithDeny.String(),
		"optimized with deny not working properly")
}
