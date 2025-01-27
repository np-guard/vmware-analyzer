package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
	"testing"

	"github.com/stretchr/testify/require"
)

func newDummyGroupTerm(name string, neg bool) *groupAtomicTerm {
	nsxGroup := nsx.Group{DisplayName: &name}
	group := collector.Group{Group: nsxGroup}
	dummyGroupTerm := groupAtomicTerm{group: &group, neg: neg}
	return &dummyGroupTerm
}

func TestGroupTerms(t *testing.T) {
	slytherin, gryffindor, dontCare := "Slytherin", "Gryffindor", "dontCare"
	atomicSly := newDummyGroupTerm(slytherin, false)
	atomicDontCare := newDummyGroupTerm(dontCare, false)
	atomicNegSly := newDummyGroupTerm(slytherin, true)
	atomicGry := newDummyGroupTerm(gryffindor, false)
	atomicNegGry := newDummyGroupTerm(gryffindor, true)
	disjoint := [][]string{{slytherin, gryffindor}}
	hints := Hints{GroupsDisjoint: disjoint}
	// test disjoint between atomics
	require.Equal(t, atomicGry.disjoint(atomicSly, &hints), true,
		"Slytherin and Gryffindor should be disjoint")
	require.Equal(t, atomicNegSly.disjoint(atomicNegGry, &hints), false,
		"Neg Slytherin and Neg Gryffindor should not be disjoint")
	require.Equal(t, atomicGry.disjoint(atomicDontCare, &hints), false,
		"Slytherin and dontCare should not be disjoint")
	require.Equal(t, atomicGry.disjoint(atomicNegSly, &hints), false,
		"Slytherin and Neg Gryffindor should not be disjoint")
	// test supersetOf between atomics
	require.Equal(t, atomicGry.supersetOf(atomicSly, &hints), false,
		"Gryffindor not supersetOf Slytherin")
	require.Equal(t, atomicNegSly.supersetOf(atomicNegGry, &hints), false,
		"Neg Gryffindor not supersetOf Neg Slytherin  should be disjoint")
	require.Equal(t, atomicGry.supersetOf(atomicDontCare, &hints), false,
		"Slytherin not supersetOf dontCare")
	require.Equal(t, atomicNegSly.supersetOf(atomicGry, &hints), true,
		"Slytherin neg supersetOf Gryffindor")
}

func TestSymbolicPaths(t *testing.T) {
	conjSrc, conjDst, conjEmpty := Conjunction{}, Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		atomic := newDummyGroupTerm(fmt.Sprintf("str%v", i), false)
		conjSrc = *conjSrc.add(*atomic)
		negateAtomic := atomic.negate().(groupAtomicTerm)
		conjDst = *conjDst.add(negateAtomic)
	}
	conjSymbolicPath := SymbolicPath{Src: conjSrc, Dst: conjDst, Conn: netset.AllTCPTransport()}
	fmt.Printf("\nconjSymbolicPath:\n%v\n", conjSymbolicPath.String())
	require.Equal(t, "TCP from (group = str1 and group = str2 and group = str3) to "+
		"(group != str1 and group != str2 and group != str3)",
		conjSymbolicPath.String(), "conjSymbolicPath not as expected")
	println("conjEmpty", conjEmpty.string())
	require.Equal(t, emptySet, conjEmpty.string(), "empty conjunction not as expected")
	// tests removeRedundant
	slytherin, gryffindor := "Slytherin", "Gryffindor"
	atomicSly := newDummyGroupTerm(slytherin, false)
	atomicNegSly := newDummyGroupTerm(slytherin, true)
	atomicGry := newDummyGroupTerm(gryffindor, false)
	atomicNegGry := newDummyGroupTerm(gryffindor, true)
	src := Conjunction{atomicGry, atomicNegSly}
	dst := Conjunction{atomicSly, atomicNegGry}
	path := SymbolicPath{src, dst, netset.AllTCPTransport()}
	fmt.Printf("path is %v\n", path.String())
	disjoint := [][]string{{slytherin, gryffindor}}
	hints := Hints{GroupsDisjoint: disjoint}
	pathNoRedundant := path.removeRedundant(&hints)
	fmt.Printf("pathNoRedundant:%v\n", pathNoRedundant)
	require.Equal(t, "TCP from (group = Gryffindor) to (group = Slytherin)", pathNoRedundant.String(),
		"redundant removal not working")
}

/*
// Input:
// allow symbolic path:
// src: (s1 = str1) dst: (d1 = str1) All Connection
// deny symbolic path:
// src: (s2 = str2) dst: (d2 = str2) UDP
// Output allow paths:
// src: (s1 = str1 and s2 != str2) dst (d1 = str1) All connection
// src: (s1 = str1) dst: (d1 = str1 and d2 != str2) All connection
// src: (s1 = str1) dst: (d1 = str1) ICMP, TCP
func TestComputeAllowGivenDenySingleTermEach1(t *testing.T) {
	conjSrc1, conjDst1, conjSrc2, conjDst2 := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	testSrc1 := initTestTag("s1")
	atomic1 := groupAtomicTerm{property: testSrc1, toVal: "str1"}
	conjSrc1 = *conjSrc1.add(atomic1)
	testDst1 := initTestTag("d1")
	atomicDst1 := groupAtomicTerm{property: testDst1, toVal: "str1"}
	conjDst1 = *conjDst1.add(atomicDst1)
	testSrc2 := initTestTag("s2")
	atomic2 := groupAtomicTerm{property: testSrc2, toVal: "str2"}
	conjSrc2 = *conjSrc2.add(atomic2)
	testDst2 := initTestTag("d2")
	atomicDst2 := groupAtomicTerm{property: testDst2, toVal: "str2"}
	conjDst2 = *conjDst2.add(atomicDst2)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjSrc2, Dst: conjDst2, Conn: netset.AllUDPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t, "All Connections from (s1 = str1 and s2 != str2) to (d1 = str1)\n"+
		"All Connections from (s1 = str1) to (d1 = str1 and d2 != str2)\n"+
		"ICMP,TCP from (s1 = str1) to (d1 = str1)",
		allowGivenDeny.String(), "allowGivenDeny single term computation not as expected")
}

// Input:
// allow symbolic path:
// src: (s1 = str1) dst: (d1 = str1) UDP
// deny symbolic path:
// src: (s2 = str2) dst: (d2 = str2) TCP
// Output allow paths:
// src: (s1 = str1) dst: (d1 = str1) UDP
func TestComputeAllowGivenDenySingleTermEach2(t *testing.T) {
	conjSrc1, conjDst1, conjSrc2, conjDst2 := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	testSrc1 := initTestTag("s1")
	atomic1 := groupAtomicTerm{property: testSrc1, toVal: "str1"}
	conjSrc1 = *conjSrc1.add(atomic1)
	testDst1 := initTestTag("d1")
	atomicDst1 := groupAtomicTerm{property: testDst1, toVal: "str1"}
	conjDst1 = *conjDst1.add(atomicDst1)
	testSrc2 := initTestTag("s2")
	atomic2 := groupAtomicTerm{property: testSrc2, toVal: "str2"}
	conjSrc2 = *conjSrc2.add(atomic2)
	testDst2 := initTestTag("d2")
	atomicDst2 := groupAtomicTerm{property: testDst2, toVal: "str2"}
	conjDst2 = *conjDst2.add(atomicDst2)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllUDPTransport()}
	denyPath := SymbolicPath{Src: conjSrc2, Dst: conjDst2, Conn: netset.AllTCPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	// computeAllowGivenAllowHigherDeny not optimized
	require.Equal(t, "UDP from (s1 = str1 and s2 != str2) to (d1 = str1)\n"+
		"UDP from (s1 = str1) to (d1 = str1 and d2 != str2)\nUDP from (s1 = str1) to (d1 = str1)",
		allowGivenDeny.String(), "allowGivenDeny single term computation not as expected")
	// ComputeAllowGivenDenies optimize
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allowGivenDenyPaths is %v\n", allowGivenDenyPaths.String())
	require.Equal(t, "UDP from (s1 = str1) to (d1 = str1)", allowGivenDenyPaths.String(),
		"ComputeAllowGivenDenies does not work as expected")
}

// Input:
// allow symbolic path:
// src: (s1 = str1) dst: (d1 = str1) TCP
// deny symbolic path:
// src: (s1 = str1) dst: (d1 = str2) TCP src port 0-50
// Output allow paths:
// src: (s1 = str1) dst: (d1 = str1) TCP src port TCP src-ports: 51-65535
func TestComputeAllowGivenDenySingleTermEach3(t *testing.T) {
	conjSrc1, conjDst1 := Conjunction{}, Conjunction{}
	testSrc1 := initTestTag("s1")
	atomic1 := groupAtomicTerm{property: testSrc1, toVal: "str1"}
	conjSrc1 = *conjSrc1.add(atomic1)
	testDst1 := initTestTag("d1")
	atomicDst1 := groupAtomicTerm{property: testDst1, toVal: "str1"}
	conjDst1 = *conjDst1.add(atomicDst1)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTCPTransport()}
	denyPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.NewTCPTransport(0, 50,
		netp.MinPort, netp.MaxPort)}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allowGivenDenyPaths is %v\n", allowGivenDenyPaths.String())
	require.Equal(t, "TCP src-ports: 51-65535 from (s1 = str1) to (d1 = str1)", allowGivenDenyPaths.String(),
		"ComputeAllowGivenDenies does not work as expected")
}

// Input:
// allow symbolic path:
// src: (s1 = str1) dst: (d1 = str1) TCP
// deny symbolic path:
// src: (s1 = str1) dst: (d1 = str2) TCP
// Output allow paths: empty set
func TestComputeAllowGivenDenySingleTermEach4(t *testing.T) {
	conjSrc1, conjDst1 := Conjunction{}, Conjunction{}
	testSrc1 := initTestTag("s1")
	atomic1 := groupAtomicTerm{property: testSrc1, toVal: "str1"}
	conjSrc1 = *conjSrc1.add(atomic1)
	testDst1 := initTestTag("d1")
	atomicDst1 := groupAtomicTerm{property: testDst1, toVal: "str1"}
	conjDst1 = *conjDst1.add(atomicDst1)
	path := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTCPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", path.String(), path.String())
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&path}, &SymbolicPaths{&path},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allowGivenDenyPaths is %v\n", allowGivenDenyPaths.String())
	require.Equal(t, "empty set ", allowGivenDenyPaths.String(),
		"ComputeAllowGivenDenies does not work as expected")
}

// Input:
// allow symbolic path:
// (s1 = str1 and s2 = str2 and s3 = str3)  dst: (s1 = str1 and s2 = str2 and s3 = str3) conn TCP
// deny symbolic path:
// src: (s1` = str1` and s2` = str2` and s3` = str3`) dst: (s1` = str1` and s2` = str2` and s3` = str3`) conn ALL
// src: (s1 = str1 and s2 = str2 and s3 = str3)  dst: (s1 = str1 and s2 = str2 and s3 = str3) conn UDP (no effect)
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
		atomicAllow := groupAtomicTerm{property: testAllow, toVal: fmt.Sprintf("str%v", i)}
		conjAllow = *conjAllow.add(atomicAllow)
		testDeny := initTestTag(fmt.Sprintf("s%v`", i))
		atomicDeny := groupAtomicTerm{property: testDeny, toVal: fmt.Sprintf("str%v`", i)}
		conjDeny = *conjDeny.add(atomicDeny)
	}
	allowPath := SymbolicPath{Src: conjAllow, Dst: conjAllow, Conn: netset.AllTCPTransport()}
	denyPath := SymbolicPath{Src: conjDeny, Dst: conjDeny, Conn: netset.AllTransports()}
	denyPathNoEffect := SymbolicPath{Src: conjDeny, Dst: conjDeny, Conn: netset.AllUDPTransport()}
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath},
		&SymbolicPaths{&denyPath, &denyPathNoEffect}, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.String(), denyPath.String())
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDenyPaths.String())
	require.Equal(t,
		"TCP from (s1 = str1 and s2 = str2 and s3 = str3 and s1` != str1`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3 and s2` != str2`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3 and s3` != str3`) to (s1 = str1 and s2 = str2 and s3 = str3)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s1` != str1`)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s2` != str2`)\n"+
			"TCP from (s1 = str1 and s2 = str2 and s3 = str3) to (s1 = str1 and s2 = str2 and s3 = str3 and s3` != str3`)",
		allowGivenDenyPaths.String(), "allowGivenDeny three terms computation not as expected")
}

// Input:
// allow symbolic path:
// src: src: (*) dst: (*)
// deny symbolic path:
// src: src: (s1` = str1` and s2` = str2` and s3` = str3`) UDP
// dst: (s1` = str1` and s2` = str2` and s3` = str3`)
// Output allow paths:
// src: (*) dst: (*) TCP and ICMP
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
		atomicDeny := groupAtomicTerm{property: testDeny, toVal: fmt.Sprintf("str%v`", i)}
		conjDeny = *conjDeny.add(atomicDeny)
	}
	tautologyConj := Conjunction{tautology{}}
	allowPath := SymbolicPath{Src: tautologyConj, Dst: tautologyConj, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjDeny, Dst: conjDeny, Conn: netset.AllUDPTransport()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t,
		"All Connections from (s1` != str1`) to (*)\nAll Connections from (s2` != str2`) to (*)\n"+
			"All Connections from (s3` != str3`) to (*)\nAll Connections from (*) to (s1` != str1`)\n"+
			"All Connections from (*) to (s2` != str2`)\nAll Connections from (*) to (s3` != str3`)\n"+
			"ICMP,TCP from (*) to (*)", allowGivenDeny.String(),
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
		atomicAllow := groupAtomicTerm{property: testAllow, toVal: fmt.Sprintf("str%v`", i)}
		conjAllow = *conjAllow.add(atomicAllow)
	}
	fmt.Printf("conjAllow is %v\nisEmptySet%v\n\n", conjAllow.string(),
		conjAllow.isEmptySet(&Hints{GroupsDisjoint: [][]string{}}))
	tautologyConj := Conjunction{tautology{}}
	allowPath := SymbolicPath{Src: conjAllow, Dst: conjAllow, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: tautologyConj, Dst: tautologyConj, Conn: netset.AllTransports()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t, emptySet, allowGivenDeny.String(),
		"allowGivenDeny deny tautology computation not as expected")
}

// Input:
// allow symbolic path:
// src: (tag = t0) dst: (tag = t1) TCP
// src: (tag = t2) dst: (tag = t3)
// deny symbolic path:
// src: (segment = s0) dst: (segment = s1)
// src: (segment = s2) dst: (segment = s3)
// src: (segment = s4) dst: (segment = s5)
// Output allow paths:
// src: (tag = t0 and segment != s0 and segment != s2 and segment != s4) dst: (tag = t1) TCP
// src: (tag = t0 and segment != s0 and segment != s2) dst: (tag = t1 and segment != s5) TCP
// src: (tag = t0 and segment != s0 and segment != s4) dst: (tag = t1 and segment != s3) TCP
// src: (tag = t0 and segment != s0) dst: (tag = t1 and segment != s3 and segment != s5) TCP
// src: (tag = t0 and segment != s2 and segment != s4) dst: (tag = t1 and segment != s1) TCP
// src: (tag = t0 and segment != s2) dst: (tag = t1 and segment != s1 and segment != s5) TCP
// src: (tag = t0 and segment != s4) dst: (tag = t1 and segment != s1 and segment != s3) TCP
// src: (tag = t0) dst: (tag = t1 and segment != s1 and segment != s3 and segment != s5) TCP
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
			atomicAllowSrc := &groupAtomicTerm{property: testTag, toVal: fmt.Sprintf("t%v", 2*i)}
			atomicAllowDst := &groupAtomicTerm{property: testTag, toVal: fmt.Sprintf("t%v", 2*i+1)}
			conjAllowSrc := Conjunction{atomicAllowSrc}
			conjAllowDst := Conjunction{atomicAllowDst}
			allowPaths = append(allowPaths, &SymbolicPath{Src: conjAllowSrc, Dst: conjAllowDst, Conn: netset.AllTCPTransport()})
		}
		atomicDenySrc := &groupAtomicTerm{property: testSegment, toVal: fmt.Sprintf("s%v", 2*i)}
		atomicDenyDst := &groupAtomicTerm{property: testSegment, toVal: fmt.Sprintf("s%v", 2*i+1)}
		conjDenySrc := Conjunction{atomicDenySrc}
		conjDenyDst := Conjunction{atomicDenyDst}
		denyPaths = append(denyPaths, &SymbolicPath{Src: conjDenySrc, Dst: conjDenyDst, Conn: netset.AllTransports()})
	}
	fmt.Printf("allowPaths:\n%v\ndenyPaths:\n%v\n", allowPaths.String(), denyPaths.String())
	res := ComputeAllowGivenDenies(&allowPaths, &denyPaths, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("ComputeAllowGivenDenies:\n%v\n", res.String())
	require.Equal(t,
		"TCP from (tag = t0 and segment != s0 and segment != s2 and segment != s4) to (tag = t1)\n"+
			"TCP from (tag = t0 and segment != s0 and segment != s2) to (tag = t1 and segment != s5)\n"+
			"TCP from (tag = t0 and segment != s0 and segment != s4) to (tag = t1 and segment != s3)\n"+
			"TCP from (tag = t0 and segment != s0) to (tag = t1 and segment != s3 and segment != s5)\n"+
			"TCP from (tag = t0 and segment != s2 and segment != s4) to (tag = t1 and segment != s1)\n"+
			"TCP from (tag = t0 and segment != s2) to (tag = t1 and segment != s1 and segment != s5)\n"+
			"TCP from (tag = t0 and segment != s4) to (tag = t1 and segment != s1 and segment != s3)\n"+
			"TCP from (tag = t0) to (tag = t1 and segment != s1 and segment != s3 and segment != s5)\n"+
			"TCP from (tag = t2 and segment != s0 and segment != s2 and segment != s4) to (tag = t3)\n"+
			"TCP from (tag = t2 and segment != s0 and segment != s2) to (tag = t3 and segment != s5)\n"+
			"TCP from (tag = t2 and segment != s0 and segment != s4) to (tag = t3 and segment != s3)\n"+
			"TCP from (tag = t2 and segment != s0) to (tag = t3 and segment != s3 and segment != s5)\n"+
			"TCP from (tag = t2 and segment != s2 and segment != s4) to (tag = t3 and segment != s1)\n"+
			"TCP from (tag = t2 and segment != s2) to (tag = t3 and segment != s1 and segment != s5)\n"+
			"TCP from (tag = t2 and segment != s4) to (tag = t3 and segment != s1 and segment != s3)\n"+
			"TCP from (tag = t2) to (tag = t3 and segment != s1 and segment != s3 and segment != s5)",
		res.String(), "ComputeAllowGivenDenies computation not as expected")
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
	atomic1 := groupAtomicTerm{property: testSrc1, toVal: "str1"}
	conjSrc1 = *conjSrc1.add(atomic1)
	testDst1 := initTestTag("d1")
	atomicDst1 := groupAtomicTerm{property: testDst1, toVal: "str1"}
	conjDst1 = *conjDst1.add(atomicDst1)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: Conjunction{tautology{}}, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTransports()}
	allowWithDeny := ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allow path: %v with higher priority deny path:%v is:\n%v\n\n",
		allowPath.String(), denyPath.String(), allowWithDeny.String())
	require.Equal(t, "All Connections from (s1 = str1) to (d1 != str1)", allowWithDeny.String(),
		"optimized with deny not working properly")
}

// conj1: (s1 = str1)
// conj2: (s1 = str1), (s2 = str2)
// conj3: (s1 = str1), (s2 = str2), (s3 = str3)
// path1: conj1 to conj1 TCP
// path1Tag: conj1 to conj1 All
// path2: conj2 to conj2 TCP
// path3: conj3 to conj3 TCP
// path4: conj1 to conj2 TCP
// path5: conj3 to conj2 TCP
// tests:
// path1 is implied by all paths
// path1Tag is not implied by path3
// path2 is implied by path3 and path5, is not implied by path4
// path5 is implied by path3 but not by path2
func TestSymbolicPathsImplied(t *testing.T) {
	conj1, conj2, conj3 := Conjunction{}, Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		testAllow := initTestTag(fmt.Sprintf("s%v", i))
		atomicAllow := groupAtomicTerm{property: testAllow, toVal: fmt.Sprintf("str%v", i)}
		if i < 2 {
			conj1 = *conj1.add(atomicAllow)
		}
		if i < 3 {
			conj2 = *conj2.add(atomicAllow)
		}
		conj3 = *conj3.add(atomicAllow)
	}
	path1 := &SymbolicPath{Src: conj1, Dst: conj1, Conn: netset.AllTCPTransport()}
	path1Tag := &SymbolicPath{Src: conj1, Dst: conj1, Conn: netset.AllTransports()}
	path2 := &SymbolicPath{Src: conj2, Dst: conj2, Conn: netset.AllTCPTransport()}
	path3 := &SymbolicPath{Src: conj3, Dst: conj3, Conn: netset.AllTCPTransport()}
	path4 := &SymbolicPath{Src: conj1, Dst: conj2, Conn: netset.AllTCPTransport()}
	path5 := &SymbolicPath{Src: conj3, Dst: conj2, Conn: netset.AllTCPTransport()}
	// tests:
	require.Equal(t, true,
		path1.isSubset(path1, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSubset(path1Tag, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSubset(path2, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSubset(path3, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSubset(path4, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSubset(path5, &Hints{GroupsDisjoint: [][]string{}}), "path1 should be implied by all paths")
	require.Equal(t, true, !path1Tag.isSubset(path3, &Hints{GroupsDisjoint: [][]string{}}),
		"path3 does not imply path1Tag due to the connection")
	require.Equal(t, true, path2.isSubset(path3, &Hints{GroupsDisjoint: [][]string{}}) &&
		path2.isSubset(path5, &Hints{GroupsDisjoint: [][]string{}}) &&
		!path2.isSubset(path4, &Hints{GroupsDisjoint: [][]string{}}),
		"path2 should be implied by path3 and path5, is not implied by path4")
}
*/
