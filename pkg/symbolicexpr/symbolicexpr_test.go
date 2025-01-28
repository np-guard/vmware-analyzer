package symbolicexpr

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

func newDummyGroupTerm(name string, neg bool) *groupAtomicTerm {
	nsxGroup := nsx.Group{DisplayName: &name}
	group := collector.Group{Group: nsxGroup}
	dummyGroupTerm := groupAtomicTerm{group: &group, atomicTerm: atomicTerm{neg: neg}}
	return &dummyGroupTerm
}

func TestTagTerms(t *testing.T) {
	slytherin, gryffindor, dontCare := "Slytherin", "Gryffindor", "dontCare"
	atomicSly := newTagTerm(slytherin, false)
	atomicDontCare := newTagTerm(dontCare, false)
	atomicNegSly := newTagTerm(slytherin, true)
	atomicGry := newTagTerm(gryffindor, false)
	atomicNegGry := newTagTerm(gryffindor, true)
	fmt.Println("atomicSly is", atomicSly.string())
	fmt.Println("atomicNegSly is", atomicNegSly.string())
	fmt.Println("atomicGry is", atomicGry.string())
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

// Input:
// allow symbolic path:
// src: (tag = src1) dst: (tag = dst1) All Connection
// deny symbolic path:
// src: (tag = src2) dst: (tag = dst2) UDP
// Output allow paths:
// src: (tag = src1 and tag != src2) dst (tag = dst1) All connection
// src: (tag = src1) dst: (tag = dst1 and tag != dst2) All connection
// src: (tag = src1) dst: (tag = dst2) ICMP, TCP
func TestComputeAllowGivenDenySingleTermEach1(t *testing.T) {
	conjSrc1, conjDst1, conjSrc2, conjDst2 := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	atomic1 := newTagTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomic1)
	atomicDst1 := newTagTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
	atomic2 := newTagTerm("src2", false)
	conjSrc2 = *conjSrc2.add(*atomic2)
	atomicDst2 := newTagTerm("dst2", false)
	conjDst2 = *conjDst2.add(*atomicDst2)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjSrc2, Dst: conjDst2, Conn: netset.AllUDPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t, "All Connections from (tag = src1 and tag != src2) to (tag = dst1)\n"+
		"All Connections from (tag = src1) to (tag = dst1 and tag != dst2)\n"+
		"ICMP,TCP from (tag = src1) to (tag = dst1)",
		allowGivenDeny.String(), "allowGivenDeny single term computation not as expected")
}

// Input:
// allow symbolic path:
// src: (tag = src1) dst: (tag = dst1) UDP
// deny symbolic path:
// src: (tag = src2) dst: (tag = dst2) TCP
// Output allow paths:
// src: (tag = src1) dst: (tag = dst1) UDP
func TestComputeAllowGivenDenySingleTermEach2(t *testing.T) {
	conjSrc1, conjDst1, conjSrc2, conjDst2 := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	atomic1 := newTagTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomic1)
	atomicDst1 := newTagTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
	atomic2 := newTagTerm("src2", false)
	conjSrc2 = *conjSrc2.add(*atomic2)
	atomicDst2 := newTagTerm("dst2", false)
	conjDst2 = *conjDst2.add(*atomicDst2)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllUDPTransport()}
	denyPath := SymbolicPath{Src: conjSrc2, Dst: conjDst2, Conn: netset.AllTCPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	// computeAllowGivenAllowHigherDeny not optimized
	require.Equal(t, "UDP from (tag = src1 and tag != src2) to (tag = dst1)\n"+
		"UDP from (tag = src1) to (tag = dst1 and tag != dst2)\nUDP from (tag = src1) to (tag = dst1)",
		allowGivenDeny.String(), "allowGivenDeny single term computation not as expected")
	// ComputeAllowGivenDenies optimize
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allowGivenDenyPaths is %v\n", allowGivenDenyPaths.String())
	require.Equal(t, "UDP from (tag = src1) to (tag = dst1)", allowGivenDenyPaths.String(),
		"ComputeAllowGivenDenies does not work as expected")
}

// Input:
// allow symbolic path:
// src: (group = src1) dst: (group = dst1) TCP
// deny symbolic path:
// src: (group = src1) dst: (group = dst2) TCP src port 0-50
// Output allow paths:
// src: (group = src1) dst: (group = dst1) TCP src port TCP src-ports: 51-65535
func TestComputeAllowGivenDenySingleTermEach3(t *testing.T) {
	conjSrc1, conjDst1 := Conjunction{}, Conjunction{}
	atomic1 := newDummyGroupTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomic1)
	atomicDst1 := newDummyGroupTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTCPTransport()}
	denyPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.NewTCPTransport(0, 50,
		netp.MinPort, netp.MaxPort)}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allowGivenDenyPaths is %v\n", allowGivenDenyPaths.String())
	require.Equal(t, "TCP src-ports: 51-65535 from (group = src1) to (group = dst1)", allowGivenDenyPaths.String(),
		"ComputeAllowGivenDenies does not work as expected")
}

// Input:
// allow symbolic path:
// src: (s1 = src1) dst: (d1 = dst1) TCP
// deny symbolic path:
// src: (s1 = src1) dst: (d1 = dst2) TCP
// Output allow paths: empty set
func TestComputeAllowGivenDenySingleTermEach4(t *testing.T) {
	conjSrc1, conjDst1 := Conjunction{}, Conjunction{}
	atomic1 := newDummyGroupTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomic1)
	atomicDst1 := newDummyGroupTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
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
// (s1 = src1 and s2 = src2 and s3 = src3)  dst: (s1 = str1 and s2 = str2 and s3 = str3) conn TCP
// deny symbolic path:
// src: (group` = src1` and group` = src2` and group` = src3`)
// dst: (group` = src1` and group` = str2` and group` = str3`) conn ALL
// src: (group = src1 and group = src2 and group = src3)
// dst: (group = dst1 and group = dst2 and group = dst3) conn UDP (no effect)
// Output allow paths:
// src: (group = src1 and group = src2 and group = src3 and group != src1`)
// dst: (group = dst1 and group = dst2 and group = dst3)
// src: (group = src1 and group = src2 and group = src3 and group != src2`)
// dst: (group = dst1 and group = dst2 and group = dst3)
// src: (group = src1 and group = src2 and group = src3 and group != src3`)
// dst: (group = dst1 and group = dst2 and group = dst3)
// src: (group = src1 and group = src2 and group = src3)
// dst: (group = dst1 and group = str2 and group = dst3 and group != dst1`)
// src: (group = src1 and group = src2 and group = src3)
// dst: (group = dst1 and group = str2 and group = dst3 and group != dst2`)
// src: (group = src1 and group = src2 and group = src3)
// dst: (group = dst1 and group = str2 and group = dst3 and group != dst3`)
func TestComputeAllowGivenDenyThreeTermsEach(t *testing.T) {
	conjAllowSrc, conjAllowDst, conjDenySrc, conjDenyDst := Conjunction{}, Conjunction{}, Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		atomicAllowSrc := newDummyGroupTerm(fmt.Sprintf("src%v", i), false)
		conjAllowSrc = *conjAllowSrc.add(*atomicAllowSrc)
		atomicAllowDst := newDummyGroupTerm(fmt.Sprintf("dst%v", i), false)
		conjAllowDst = *conjAllowDst.add(*atomicAllowDst)
		atomicDenySrc := newDummyGroupTerm(fmt.Sprintf("src%v`", i), false)
		conjDenySrc = *conjDenySrc.add(*atomicDenySrc)
		atomicDenyDst := newDummyGroupTerm(fmt.Sprintf("dst%v`", i), false)
		conjDenyDst = *conjDenyDst.add(*atomicDenyDst)
	}
	allowPath := SymbolicPath{Src: conjAllowSrc, Dst: conjAllowDst, Conn: netset.AllTCPTransport()}
	denyPath := SymbolicPath{Src: conjDenySrc, Dst: conjDenyDst, Conn: netset.AllTransports()}
	denyPathNoEffect := SymbolicPath{Src: conjDenySrc, Dst: conjDenyDst, Conn: netset.AllUDPTransport()}
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath},
		&SymbolicPaths{&denyPath, &denyPathNoEffect}, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.String(), denyPath.String())
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDenyPaths.String())
	require.Equal(t,
		"TCP from (group = src1 and group = src2 and group = src3 and group != src1`) to"+
			" (group = dst1 and group = dst2 and group = dst3)\n"+
			"TCP from (group = src1 and group = src2 and group = src3 and group != src2`) to "+
			"(group = dst1 and group = dst2 and group = dst3)\n"+
			"TCP from (group = src1 and group = src2 and group = src3 and group != src3`) to"+
			" (group = dst1 and group = dst2 and group = dst3)\n"+
			"TCP from (group = src1 and group = src2 and group = src3) to "+
			"(group = dst1 and group = dst2 and group = dst3 and group != dst1`)\n"+
			"TCP from (group = src1 and group = src2 and group = src3) to "+
			"(group = dst1 and group = dst2 and group = dst3 and group != dst2`)\n"+
			"TCP from (group = src1 and group = src2 and group = src3) to "+
			"(group = dst1 and group = dst2 and group = dst3 and group != dst3`)",
		allowGivenDenyPaths.String(), "allowGivenDeny three terms computation not as expected")
}

// Input:
// allow symbolic path:
// src: src: (*) dst: (*)
// deny symbolic path:
// src: src: (group = src1 and group = src2 and group = src3) UDP
// dst: (group = dst1 and group = dst2 and group = dst3)
// Output allow paths:
// src: (*) dst: (*) TCP and ICMP
// src: (group != src1`) dst: (*)
// src: (group != src2`) dst: (*)
// src: (group != src3`) dst: (*)
// src: (*) dst: (group != dst1`)
// src: (*) dst: (group != dst2`)
// src: (*) dst: (group != dst3`)
func TestComputeAllowGivenDenyAllowTautology(t *testing.T) {
	conjDenySrc, conjDenyDst := Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		atomicDenySrc := newDummyGroupTerm(fmt.Sprintf("src%v`", i), false)
		conjDenySrc = *conjDenySrc.add(*atomicDenySrc)
		atomicDenyDst := newDummyGroupTerm(fmt.Sprintf("dst%v`", i), false)
		conjDenyDst = *conjDenyDst.add(*atomicDenyDst)
	}
	tautologyConj := Conjunction{tautology{}}
	allowPath := SymbolicPath{Src: tautologyConj, Dst: tautologyConj, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjDenySrc, Dst: conjDenyDst, Conn: netset.AllUDPTransport()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t,
		"All Connections from (group != src1`) to (*)\nAll Connections from (group != src2`) to (*)\n"+
			"All Connections from (group != src3`) to (*)\nAll Connections from (*) to (group != dst1`)\n"+
			"All Connections from (*) to (group != dst2`)\nAll Connections from (*) to (group != dst3`)\n"+
			"ICMP,TCP from (*) to (*)", allowGivenDeny.String(),
		"allowGivenDeny allow tautology computation not as expected")
}

// Input:
// allow symbolic path:
// src: (group = src1 and group = src2 and group = src3) dst: (group = dst1 and group = dst2 and group = dst3)
// deny symbolic path:
// src: * dst: *
// Output allow paths: empty
func TestComputeAllowGivenDenyDenyTautology(t *testing.T) {
	conjAllowSrc, conjAllowDst := Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		atomicAllowSrc := newDummyGroupTerm(fmt.Sprintf("src%v", i), false)
		conjAllowSrc = *conjAllowSrc.add(*atomicAllowSrc)
		atomicAllowDst := newDummyGroupTerm(fmt.Sprintf("dst%v", i), false)
		conjAllowDst = *conjAllowDst.add(*atomicAllowDst)
	}
	tautologyConj := Conjunction{tautology{}}
	allowPath := SymbolicPath{Src: conjAllowSrc, Dst: conjAllowDst, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: tautologyConj, Dst: tautologyConj, Conn: netset.AllTransports()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t, emptySet, allowGivenDeny.String(),
		"allowGivenDeny deny tautology computation not as expected")
}

// Input:
// allow symbolic path:
// src: (group = t0) dst: (group = t1) TCP
// src: (group = t2) dst: (group = t3)
// deny symbolic path:
// src: (group = s0) dst: (group = s1)
// src: (group = s2) dst: (group = s3)
// src: (group = s4) dst: (group = s5)
// Output allow paths:
// src: (group = t0 and group != s0 and group != s2 and group != s4) dst: (group = t1) TCP
// src: (group = t0 and group != s0 and group != s2) dst: (group = t1 and group != s5) TCP
// src: (group = t0 and group != s0 and group != s4) dst: (group = t1 and group != s3) TCP
// src: (group = t0 and group != s0) dst: (group = t1 and group != s3 and group != s5) TCP
// src: (group = t0 and group != s2 and group != s4) dst: (group = t1 and group != s1) TCP
// src: (group = t0 and group != s2) dst: (group = t1 and group != s1 and group != s5) TCP
// src: (group = t0 and group != s4) dst: (group = t1 and group != s1 and group != s3) TCP
// src: (group = t0) dst: (group = t1 and group != s1 and group != s3 and group != s5) TCP
// src: (group = t2 and group != s0 and group != s2 and group != s4) dst: (group = t3)
// src: (group = t2 and group != s0 and group != s2) dst: (group = t3 and group != s5)
// src: (group = t2 and group != s0 and group != s4) dst: (group = t3 and group != s3)
// src: (group = t2 and group != s0) dst: (group = t3 and group != s3 and group != s5)
// src: (group = t2 and group != s2 and group != s4) dst: (group = t3 and group != s1)
// src: (group = t2 and group != s2) dst: (group = t3 and group != s1 and group != s5)
// src: (group = t2 and group != s4) dst: (group = t3 and group != s1 and group != s3)
// src: (group = t2) dst: (group = t3 and group != s1 and group != s3 and group != s5)
func TestComputeAllowGivenDenies(t *testing.T) {
	allowPaths, denyPaths := SymbolicPaths{}, SymbolicPaths{}

	for i := 0; i < 3; i++ {
		if i < 2 {
			atomicAllowSrc := newDummyGroupTerm(fmt.Sprintf("t%v", 2*i), false)
			atomicAllowDst := newDummyGroupTerm(fmt.Sprintf("t%v", 2*i+1), false)
			conjAllowSrc := Conjunction{atomicAllowSrc}
			conjAllowDst := Conjunction{atomicAllowDst}
			allowPaths = append(allowPaths, &SymbolicPath{Src: conjAllowSrc, Dst: conjAllowDst, Conn: netset.AllTCPTransport()})
		}
		atomicDenySrc := newDummyGroupTerm(fmt.Sprintf("s%v", 2*i), false)
		atomicDenyDst := newDummyGroupTerm(fmt.Sprintf("s%v", 2*i+1), false)
		conjDenySrc := Conjunction{atomicDenySrc}
		conjDenyDst := Conjunction{atomicDenyDst}
		denyPaths = append(denyPaths, &SymbolicPath{Src: conjDenySrc, Dst: conjDenyDst, Conn: netset.AllTransports()})
	}
	fmt.Printf("allowPaths:\n%v\ndenyPaths:\n%v\n", allowPaths.String(), denyPaths.String())
	res := ComputeAllowGivenDenies(&allowPaths, &denyPaths, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("ComputeAllowGivenDenies:\n%v\n", res.String())
	require.Equal(t,
		"TCP from (group = t0 and group != s0 and group != s2 and group != s4) to (group = t1)\n"+
			"TCP from (group = t0 and group != s0 and group != s2) to (group = t1 and group != s5)\n"+
			"TCP from (group = t0 and group != s0 and group != s4) to (group = t1 and group != s3)\n"+
			"TCP from (group = t0 and group != s0) to (group = t1 and group != s3 and group != s5)\n"+
			"TCP from (group = t0 and group != s2 and group != s4) to (group = t1 and group != s1)\n"+
			"TCP from (group = t0 and group != s2) to (group = t1 and group != s1 and group != s5)\n"+
			"TCP from (group = t0 and group != s4) to (group = t1 and group != s1 and group != s3)\n"+
			"TCP from (group = t0) to (group = t1 and group != s1 and group != s3 and group != s5)\n"+
			"TCP from (group = t2 and group != s0 and group != s2 and group != s4) to (group = t3)\n"+
			"TCP from (group = t2 and group != s0 and group != s2) to (group = t3 and group != s5)\n"+
			"TCP from (group = t2 and group != s0 and group != s4) to (group = t3 and group != s3)\n"+
			"TCP from (group = t2 and group != s0) to (group = t3 and group != s3 and group != s5)\n"+
			"TCP from (group = t2 and group != s2 and group != s4) to (group = t3 and group != s1)\n"+
			"TCP from (group = t2 and group != s2) to (group = t3 and group != s1 and group != s5)\n"+
			"TCP from (group = t2 and group != s4) to (group = t3 and group != s1 and group != s3)\n"+
			"TCP from (group = t2) to (group = t3 and group != s1 and group != s3 and group != s5)",
		res.String(), "ComputeAllowGivenDenies computation not as expected")
}

// Input:
// allow symbolic path:
// group = src1 to *
// deny symbolic path:
// (group = src1) to (d1 = dst1)
// Output allow paths: (group = str1) to (d1 != dst1)
func TestAllowDenyOptimizeEmptyPath(t *testing.T) {
	conjSrc1, conjDst1 := Conjunction{}, Conjunction{}
	atomicSrc1 := newDummyGroupTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomicSrc1)
	atomicDst1 := newDummyGroupTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: Conjunction{tautology{}}, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTransports()}
	allowWithDeny := ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allow path: %v with higher priority deny path:%v is:\n%v\n\n",
		allowPath.String(), denyPath.String(), allowWithDeny.String())
	require.Equal(t, "All Connections from (group = src1) to (group != dst1)", allowWithDeny.String(),
		"optimized with deny not working properly")
}

// conj1: (group = str1)
// conj2: (group = str1), (s2 = str2)
// conj3: (group = str1), (s2 = str2), (s3 = str3)
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
		atomicAllow := newDummyGroupTerm(fmt.Sprintf("str%v", i), false)
		if i < 2 {
			conj1 = *conj1.add(*atomicAllow)
		}
		if i < 3 {
			conj2 = *conj2.add(*atomicAllow)
		}
		conj3 = *conj3.add(*atomicAllow)
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
