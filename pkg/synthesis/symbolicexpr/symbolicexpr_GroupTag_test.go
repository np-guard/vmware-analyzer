package symbolicexpr

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func NewDummyGroupTerm(name string, neg bool) *groupAtomicTerm {
	nsxGroup := nsx.Group{DisplayName: &name}
	group := collector.Group{Group: nsxGroup}
	dummyGroupTerm := groupAtomicTerm{group: &group, atomicTerm: atomicTerm{neg: neg}}
	return &dummyGroupTerm
}

func TestTagTerms(t *testing.T) {
	slytherin, gryffindor, dontCare := "Slytherin", "Gryffindor", "dontCare"
	atomicSly := NewTagTerm(slytherin, false)
	atomicDontCare := NewTagTerm(dontCare, false)
	atomicNegSly := NewTagTerm(slytherin, true)
	atomicGry := NewTagTerm(gryffindor, false)
	atomicNegGry := NewTagTerm(gryffindor, true)
	fmt.Println("atomicSly is", atomicSly.String())
	fmt.Println("atomicNegSly is", atomicNegSly.String())
	fmt.Println("atomicGry is", atomicGry.String())
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
		atomic := NewDummyGroupTerm(fmt.Sprintf("str%v", i), false)
		conjSrc = *conjSrc.add(*atomic)
		negateAtomic := atomic.negate().(groupAtomicTerm)
		conjDst = *conjDst.add(negateAtomic)
	}
	conjSymbolicPath := SymbolicPath{Src: conjSrc, Dst: conjDst, Conn: netset.AllTCPTransport()}
	fmt.Printf("\nconjSymbolicPath:\n%v\n", conjSymbolicPath.String())
	require.Equal(t, "src: (group = str1 and group = str2 and group = str3) dst: "+
		"(group != str1 and group != str2 and group != str3) conn: TCP",
		conjSymbolicPath.String(), "conjSymbolicPath not as expected")
	println("conjEmpty", conjEmpty.String())
	require.Equal(t, emptySet, conjEmpty.String(), "empty conjunction not as expected")
	// tests removeRedundant
	slytherin, gryffindor := "Slytherin", "Gryffindor"
	atomicSly := NewDummyGroupTerm(slytherin, false)
	atomicNegSly := NewDummyGroupTerm(slytherin, true)
	atomicGry := NewDummyGroupTerm(gryffindor, false)
	atomicNegGry := NewDummyGroupTerm(gryffindor, true)
	src := Conjunction{atomicGry, atomicNegSly}
	dst := Conjunction{atomicSly, atomicNegGry}
	path := SymbolicPath{src, dst, netset.AllTCPTransport()}
	fmt.Printf("path is %v\n", path.String())
	disjoint := [][]string{{slytherin, gryffindor}}
	hints := Hints{GroupsDisjoint: disjoint}
	pathNoRedundant := path.removeRedundant(&hints)
	fmt.Printf("pathNoRedundant:%v\n", pathNoRedundant)
	require.Equal(t, "src: (group = Gryffindor) dst: (group = Slytherin) conn: TCP", pathNoRedundant.String(),
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
	atomic1 := NewTagTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomic1)
	atomicDst1 := NewTagTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
	atomic2 := NewTagTerm("src2", false)
	conjSrc2 = *conjSrc2.add(*atomic2)
	atomicDst2 := NewTagTerm("dst2", false)
	conjDst2 = *conjDst2.add(*atomicDst2)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjSrc2, Dst: conjDst2, Conn: netset.AllUDPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t, "src: (tag = src1 and tag != src2) dst: (tag = dst1) conn: All Connections\n"+
		"src: (tag = src1) dst: (tag = dst1 and tag != dst2) conn: All Connections\n"+
		"src: (tag = src1) dst: (tag = dst1) conn: ICMP,TCP",
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
	atomic1 := NewTagTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomic1)
	atomicDst1 := NewTagTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
	atomic2 := NewTagTerm("src2", false)
	conjSrc2 = *conjSrc2.add(*atomic2)
	atomicDst2 := NewTagTerm("dst2", false)
	conjDst2 = *conjDst2.add(*atomicDst2)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllUDPTransport()}
	denyPath := SymbolicPath{Src: conjSrc2, Dst: conjDst2, Conn: netset.AllTCPTransport()}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	// computeAllowGivenAllowHigherDeny not optimized
	require.Equal(t, "src: (tag = src1 and tag != src2) dst: (tag = dst1) conn: UDP\n"+
		"src: (tag = src1) dst: (tag = dst1 and tag != dst2) conn: UDP\nsrc: (tag = src1) dst: (tag = dst1) conn: UDP",
		allowGivenDeny.String(), "allowGivenDeny single term computation not as expected")
	// ComputeAllowGivenDenies optimize
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allowGivenDenyPaths is %v\n", allowGivenDenyPaths.String())
	require.Equal(t, "src: (tag = src1) dst: (tag = dst1) conn: UDP", allowGivenDenyPaths.String(),
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
	atomic1 := NewDummyGroupTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomic1)
	atomicDst1 := NewDummyGroupTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTCPTransport()}
	denyPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.NewTCPTransport(0, 50,
		netp.MinPort, netp.MaxPort)}
	fmt.Printf("allowPath is %v\ndenyPath is %v\n", allowPath.String(), denyPath.String())
	allowGivenDenyPaths := *ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allowGivenDenyPaths is %v\n", allowGivenDenyPaths.String())
	require.Equal(t, "src: (group = src1) dst: (group = dst1) conn: TCP src-ports: 51-65535", allowGivenDenyPaths.String(),
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
	atomic1 := NewDummyGroupTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomic1)
	atomicDst1 := NewDummyGroupTerm("dst1", false)
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
		atomicAllowSrc := NewDummyGroupTerm(fmt.Sprintf("src%v", i), false)
		conjAllowSrc = *conjAllowSrc.add(*atomicAllowSrc)
		atomicAllowDst := NewDummyGroupTerm(fmt.Sprintf("dst%v", i), false)
		conjAllowDst = *conjAllowDst.add(*atomicAllowDst)
		atomicDenySrc := NewDummyGroupTerm(fmt.Sprintf("src%v`", i), false)
		conjDenySrc = *conjDenySrc.add(*atomicDenySrc)
		atomicDenyDst := NewDummyGroupTerm(fmt.Sprintf("dst%v`", i), false)
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
		"src: (group = src1 and group = src2 and group = src3 and group != src1`) dst:"+
			" (group = dst1 and group = dst2 and group = dst3) conn: TCP\n"+
			"src: (group = src1 and group = src2 and group = src3 and group != src2`) dst: "+
			"(group = dst1 and group = dst2 and group = dst3) conn: TCP\n"+
			"src: (group = src1 and group = src2 and group = src3 and group != src3`) dst:"+
			" (group = dst1 and group = dst2 and group = dst3) conn: TCP\n"+
			"src: (group = src1 and group = src2 and group = src3) dst: "+
			"(group = dst1 and group = dst2 and group = dst3 and group != dst1`) conn: TCP\n"+
			"src: (group = src1 and group = src2 and group = src3) dst: "+
			"(group = dst1 and group = dst2 and group = dst3 and group != dst2`) conn: TCP\n"+
			"src: (group = src1 and group = src2 and group = src3) dst: "+
			"(group = dst1 and group = dst2 and group = dst3 and group != dst3`) conn: TCP",
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
func TestComputeAllowGivenDenyAllowAllGroup(t *testing.T) {
	conjDenySrc, conjDenyDst := Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		atomicDenySrc := NewDummyGroupTerm(fmt.Sprintf("src%v`", i), false)
		conjDenySrc = *conjDenySrc.add(*atomicDenySrc)
		atomicDenyDst := NewDummyGroupTerm(fmt.Sprintf("dst%v`", i), false)
		conjDenyDst = *conjDenyDst.add(*atomicDenyDst)
	}
	allGroupConj := Conjunction{allGroup{}}
	allowPath := SymbolicPath{Src: allGroupConj, Dst: allGroupConj, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjDenySrc, Dst: conjDenyDst, Conn: netset.AllUDPTransport()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t,
		"src: (group != src1`) dst: (*) conn: All Connections\n"+
			"src: (group != src2`) dst: (*) conn: All Connections\nsrc: (group != src3`) dst: (*) conn: All Connections\n"+
			"src: (*) dst: (group != dst1`) conn: All Connections\n"+
			"src: (*) dst: (group != dst2`) conn: All Connections\nsrc: (*) dst: (group != dst3`) conn: All Connections\n"+
			"src: (*) dst: (*) conn: ICMP,TCP", allowGivenDeny.String(),
		"allowGivenDeny allow allGroup computation not as expected")
}

// Input:
// allow symbolic path:
// src: (group = src1 and group = src2 and group = src3) dst: (group = dst1 and group = dst2 and group = dst3)
// deny symbolic path:
// src: * dst: *
// Output allow paths: empty
func TestComputeAllowGivenDenyDenyAllGroup(t *testing.T) {
	conjAllowSrc, conjAllowDst := Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		atomicAllowSrc := NewDummyGroupTerm(fmt.Sprintf("src%v", i), false)
		conjAllowSrc = *conjAllowSrc.add(*atomicAllowSrc)
		atomicAllowDst := NewDummyGroupTerm(fmt.Sprintf("dst%v", i), false)
		conjAllowDst = *conjAllowDst.add(*atomicAllowDst)
	}
	allGroupConj := Conjunction{allGroup{}}
	allowPath := SymbolicPath{Src: conjAllowSrc, Dst: conjAllowDst, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: allGroupConj, Dst: allGroupConj, Conn: netset.AllTransports()}
	fmt.Printf("symbolicAllow is %s\nsymbolicDeny is %s\n", allowPath.String(), denyPath.String())
	allowGivenDeny := *computeAllowGivenAllowHigherDeny(allowPath, denyPath, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("computeAllowGivenAllowHigherDeny(allowPath, denyPath) is\n%v\n", allowGivenDeny.String())
	require.Equal(t, emptySet, allowGivenDeny.String(),
		"allowGivenDeny deny allGroup computation not as expected")
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
			atomicAllowSrc := NewDummyGroupTerm(fmt.Sprintf("t%v", 2*i), false)
			atomicAllowDst := NewDummyGroupTerm(fmt.Sprintf("t%v", 2*i+1), false)
			conjAllowSrc := Conjunction{atomicAllowSrc}
			conjAllowDst := Conjunction{atomicAllowDst}
			allowPaths = append(allowPaths, &SymbolicPath{Src: conjAllowSrc, Dst: conjAllowDst, Conn: netset.AllTCPTransport()})
		}
		atomicDenySrc := NewDummyGroupTerm(fmt.Sprintf("s%v", 2*i), false)
		atomicDenyDst := NewDummyGroupTerm(fmt.Sprintf("s%v", 2*i+1), false)
		conjDenySrc := Conjunction{atomicDenySrc}
		conjDenyDst := Conjunction{atomicDenyDst}
		denyPaths = append(denyPaths, &SymbolicPath{Src: conjDenySrc, Dst: conjDenyDst, Conn: netset.AllTransports()})
	}
	fmt.Printf("allowPaths:\n%v\ndenyPaths:\n%v\n", allowPaths.String(), denyPaths.String())
	res := ComputeAllowGivenDenies(&allowPaths, &denyPaths, &Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("ComputeAllowGivenDenies:\n%v\n", res.String())
	require.Equal(t,
		"src: (group = t0 and group != s0 and group != s2 and group != s4) dst: (group = t1) conn: TCP\n"+
			"src: (group = t0 and group != s0 and group != s2) dst: (group = t1 and group != s5) conn: TCP\n"+
			"src: (group = t0 and group != s0 and group != s4) dst: (group = t1 and group != s3) conn: TCP\n"+
			"src: (group = t0 and group != s0) dst: (group = t1 and group != s3 and group != s5) conn: TCP\n"+
			"src: (group = t0 and group != s2 and group != s4) dst: (group = t1 and group != s1) conn: TCP\n"+
			"src: (group = t0 and group != s2) dst: (group = t1 and group != s1 and group != s5) conn: TCP\n"+
			"src: (group = t0 and group != s4) dst: (group = t1 and group != s1 and group != s3) conn: TCP\n"+
			"src: (group = t0) dst: (group = t1 and group != s1 and group != s3 and group != s5) conn: TCP\n"+
			"src: (group = t2 and group != s0 and group != s2 and group != s4) dst: (group = t3) conn: TCP\n"+
			"src: (group = t2 and group != s0 and group != s2) dst: (group = t3 and group != s5) conn: TCP\n"+
			"src: (group = t2 and group != s0 and group != s4) dst: (group = t3 and group != s3) conn: TCP\n"+
			"src: (group = t2 and group != s0) dst: (group = t3 and group != s3 and group != s5) conn: TCP\n"+
			"src: (group = t2 and group != s2 and group != s4) dst: (group = t3 and group != s1) conn: TCP\n"+
			"src: (group = t2 and group != s2) dst: (group = t3 and group != s1 and group != s5) conn: TCP\n"+
			"src: (group = t2 and group != s4) dst: (group = t3 and group != s1 and group != s3) conn: TCP\n"+
			"src: (group = t2) dst: (group = t3 and group != s1 and group != s3 and group != s5) conn: TCP",
		res.String(), "ComputeAllowGivenDenies computation not as expected")
}

// Input:
// allow symbolic path:
// group = src1 dst: *
// deny symbolic path:
// (group = src1) dst: (d1 = dst1)
// Output allow paths: (group = str1) dst: (d1 != dst1)
func TestAllowDenyOptimizeEmptyPath(t *testing.T) {
	conjSrc1, conjDst1 := Conjunction{}, Conjunction{}
	atomicSrc1 := NewDummyGroupTerm("src1", false)
	conjSrc1 = *conjSrc1.add(*atomicSrc1)
	atomicDst1 := NewDummyGroupTerm("dst1", false)
	conjDst1 = *conjDst1.add(*atomicDst1)
	allowPath := SymbolicPath{Src: conjSrc1, Dst: Conjunction{allGroup{}}, Conn: netset.AllTransports()}
	denyPath := SymbolicPath{Src: conjSrc1, Dst: conjDst1, Conn: netset.AllTransports()}
	allowWithDeny := ComputeAllowGivenDenies(&SymbolicPaths{&allowPath}, &SymbolicPaths{&denyPath},
		&Hints{GroupsDisjoint: [][]string{}})
	fmt.Printf("allow path: %v with higher priority deny path:%v is:\n%v\n\n",
		allowPath.String(), denyPath.String(), allowWithDeny.String())
	require.Equal(t, "src: (group = src1) dst: (group != dst1) conn: All Connections", allowWithDeny.String(),
		"optimized with deny not working properly")
}

// conj1: (group = str1)
// conj2: (group = str1), (s2 = str2)
// conj3: (group = str1), (s2 = str2), (s3 = str3)
// path1: conj1 dst: conj1 TCP
// path1Tag: conj1 dst: conj1 All
// path2: conj2 dst: conj2 TCP
// path3: conj3 dst: conj3 TCP
// path4: conj1 dst: conj2 TCP
// path5: conj3 dst: conj2 TCP
// tests:
// path1 is implied by all paths
// path1Tag is not implied by path3
// path2 is implied by path3 and path5, is not implied by path4
// path5 is implied by path3 but not by path2
func TestSymbolicPathsImplied(t *testing.T) {
	conj1, conj2, conj3 := Conjunction{}, Conjunction{}, Conjunction{}
	for i := 1; i <= 3; i++ {
		atomicAllow := NewDummyGroupTerm(fmt.Sprintf("str%v", i), false)
		if i < 2 {
			conj1 = *conj1.add(*atomicAllow)
		}
		if i < 3 {
			conj2 = *conj2.add(*atomicAllow)
		}
		conj3 = *conj3.add(*atomicAllow)
	}
	path1 := &SymbolicPath{Src: conj1, Dst: conj1, Conn: netset.AllTCPTransport()}
	path2 := &SymbolicPath{Src: conj2, Dst: conj2, Conn: netset.AllTCPTransport()}
	path2Tag := &SymbolicPath{Src: conj2, Dst: conj2, Conn: netset.AllTransports()}
	path3 := &SymbolicPath{Src: conj3, Dst: conj3, Conn: netset.AllTCPTransport()}
	path4 := &SymbolicPath{Src: conj1, Dst: conj2, Conn: netset.AllTCPTransport()}
	path5 := &SymbolicPath{Src: conj3, Dst: conj2, Conn: netset.AllTCPTransport()}
	// tests:
	require.Equal(t, true,
		path1.isSuperset(path1, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSuperset(path2, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSuperset(path3, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSuperset(path4, &Hints{GroupsDisjoint: [][]string{}}) &&
			path1.isSuperset(path5, &Hints{GroupsDisjoint: [][]string{}}),
		"path1 is a superset of all paths but path2Tag")
	require.Equal(t, true, !path1.isSuperset(path2Tag, &Hints{GroupsDisjoint: [][]string{}}),
		"path1 is not a superset of path2Tag due dst: the connection")
	require.Equal(t, true, path2.isSuperset(path3, &Hints{GroupsDisjoint: [][]string{}}) &&
		path2.isSuperset(path5, &Hints{GroupsDisjoint: [][]string{}}) &&
		!path2.isSuperset(path4, &Hints{GroupsDisjoint: [][]string{}}),
		"path2 is a superset of path3 and path5, is not a superset of path4")
}

func TestAllGroupAndTautology(t *testing.T) {
	var myAllGroup = allGroup{}
	var myTautology = tautology{}
	allGroupConj := Conjunction{myAllGroup}
	tautologyConj := Conjunction{myTautology}
	require.Equal(t, true, allGroupConj.isAllGroup())
	require.Equal(t, false, allGroupConj.isTautology())
	require.Equal(t, true, allGroupConj.hasTagOrGroupTerm())
	require.Equal(t, false, allGroupConj.hasIPBlockTerm())
	require.Equal(t, true, tautologyConj.hasIPBlockTerm())
	require.Equal(t, true, tautologyConj.hasTagOrGroupTerm())
	require.Equal(t, true, tautologyConj.isAllGroup())
	require.Equal(t, true, tautologyConj.isTautology())

	emptyHints := &Hints{GroupsDisjoint: [][]string{}}
	require.Equal(t, false, tautologyConj.isEmpty(emptyHints))
	require.Equal(t, false, allGroupConj.isEmpty(emptyHints))

	allGroupConjNeg := Conjunction{myAllGroup.negate()}
	tautologyConjNeg := Conjunction{myTautology.negate()}
	require.Equal(t, true, tautologyConjNeg.isEmpty(emptyHints))
	require.Equal(t, false, allGroupConjNeg.isEmpty(emptyHints))
	require.Equal(t, false, allGroupConjNeg.isAllGroup())
	require.Equal(t, false, allGroupConjNeg.isTautology())
	require.Equal(t, false, allGroupConjNeg.hasTagOrGroupTerm())
	require.Equal(t, false, allGroupConjNeg.hasIPBlockTerm())
	require.Equal(t, false, tautologyConjNeg.hasTagOrGroupTerm())
	require.Equal(t, false, tautologyConjNeg.hasIPBlockTerm())
	atomicTag := NewTagTerm("myTag", false)
	conjTag := Conjunction{}
	conjTag = *conjTag.add(atomicTag)
	atomicGroup := NewDummyGroupTerm("group1", false)
	conjGroup := Conjunction{}
	conjGroup = *conjGroup.add(*atomicGroup)
	conjGroupTag := Conjunction{}
	conjGroupTag = *conjGroupTag.add(atomicTag)
	conjGroupTag = *conjGroupTag.add(atomicGroup)
	ipBlock, _ := netset.IPBlockFromCidr("1.2.3.0/8")
	ipBlockTerm := NewIPBlockTerm(&topology.IPBlock{Block: ipBlock, OriginalIP: "1.2.3.0/8"})
	ipBlockConj := Conjunction{ipBlockTerm}

	// tautology is a superset of all
	require.Equal(t, true, tautologyConj.isSuperset(&allGroupConj, emptyHints))
	require.Equal(t, true, tautologyConj.isSuperset(&allGroupConjNeg, emptyHints))
	require.Equal(t, true, tautologyConj.isSuperset(&conjTag, emptyHints))
	require.Equal(t, true, tautologyConj.isSuperset(&conjGroup, emptyHints))
	require.Equal(t, true, tautologyConj.isSuperset(&ipBlockConj, emptyHints))
	// and is not disjoint to any
	require.Equal(t, false, tautologyConj.disjoint(&allGroupConj, emptyHints))
	require.Equal(t, false, tautologyConj.disjoint(&allGroupConjNeg, emptyHints))
	require.Equal(t, false, tautologyConj.disjoint(&conjTag, emptyHints))
	require.Equal(t, false, tautologyConj.disjoint(&conjGroup, emptyHints))
	require.Equal(t, false, tautologyConj.disjoint(&ipBlockConj, emptyHints))

	// 0.0.0.0/0 behaves as a tautology
	ipBlockAll, _ := netset.IPBlockFromCidr("0.0.0.0/0")
	ipBlockAllTerm := NewIPBlockTerm(&topology.IPBlock{Block: ipBlockAll, OriginalIP: "0.0.0.0/0"})
	ipBlockAllConj := Conjunction{ipBlockAllTerm}
	// superset of all
	require.Equal(t, true, ipBlockAllConj.isSuperset(&allGroupConj, emptyHints))
	require.Equal(t, true, ipBlockAllConj.isSuperset(&allGroupConjNeg, emptyHints))
	require.Equal(t, true, ipBlockAllConj.isSuperset(&conjTag, emptyHints))
	require.Equal(t, true, ipBlockAllConj.isSuperset(&conjGroup, emptyHints))
	require.Equal(t, true, ipBlockAllConj.isSuperset(&ipBlockConj, emptyHints))
	// and is not disjoint to any
	require.Equal(t, false, ipBlockAllConj.disjoint(&allGroupConj, emptyHints))
	require.Equal(t, false, ipBlockAllConj.disjoint(&allGroupConjNeg, emptyHints))
	require.Equal(t, false, ipBlockAllConj.disjoint(&conjTag, emptyHints))
	require.Equal(t, false, ipBlockAllConj.disjoint(&conjGroup, emptyHints))
	require.Equal(t, false, ipBlockAllConj.disjoint(&ipBlockConj, emptyHints))

	// allGroups is not a superSet of tautology
	require.Equal(t, false, allGroupConj.isSuperset(&tautologyConj, emptyHints))
	// it is not a superSet of Conj with ipBlockTerm
	require.Equal(t, false, allGroupConj.isSuperset(&ipBlockConj, emptyHints))
	// it is a super set of Conj with tag term, group term or both
	require.Equal(t, true, allGroupConj.isSuperset(&conjGroup, emptyHints))
	require.Equal(t, true, allGroupConj.isSuperset(&conjTag, emptyHints))
	require.Equal(t, true, allGroupConj.isSuperset(&conjGroupTag, emptyHints))

	// allGroup is disjoint to Conj with ipBlockTerm
	require.Equal(t, true, allGroupConj.disjoint(&ipBlockConj, emptyHints))
	// it is not disjoint to Conj with tag term, group term or both
	require.Equal(t, false, allGroupConj.disjoint(&conjGroup, emptyHints))
	require.Equal(t, false, allGroupConj.disjoint(&conjTag, emptyHints))
	require.Equal(t, false, allGroupConj.disjoint(&conjGroupTag, emptyHints))
}

func TestIPConjWithInternalResourceConj(t *testing.T) {
	atomicTag := NewTagTerm("myTag", false)
	conjTag := Conjunction{}
	conjTag = *conjTag.add(atomicTag)
	atomicGroup := NewDummyGroupTerm("group1", false)
	conjGroup := Conjunction{}
	conjGroup = *conjGroup.add(*atomicGroup)
	conjGroupTag := Conjunction{}
	conjGroupTag = *conjGroupTag.add(atomicTag)
	conjGroupTag = *conjGroupTag.add(atomicGroup)
	ipBlock, _ := netset.IPBlockFromCidr("1.2.3.0/8")
	ipBlockTerm := NewIPBlockTerm(&topology.IPBlock{Block: ipBlock, OriginalIP: "1.2.3.0/8"})
	ipBlockConj := Conjunction{ipBlockTerm}
	emptyHints := &Hints{GroupsDisjoint: [][]string{}}

	// conj with ipBlock is disjoint to conj with tag or group terms
	require.Equal(t, true, ipBlockConj.disjoint(&conjTag, emptyHints))
	require.Equal(t, true, ipBlockConj.disjoint(&conjGroup, emptyHints))
	require.Equal(t, true, ipBlockConj.disjoint(&conjGroupTag, emptyHints))
	// and is not a superSet of these
	require.Equal(t, false, ipBlockConj.isSuperset(&conjTag, emptyHints))
	require.Equal(t, false, ipBlockConj.isSuperset(&conjGroup, emptyHints))
	require.Equal(t, false, ipBlockConj.isSuperset(&conjGroupTag, emptyHints))
	// and vice versa
	require.Equal(t, false, conjTag.isSuperset(&ipBlockConj, emptyHints))
	require.Equal(t, false, conjGroup.isSuperset(&ipBlockConj, emptyHints))
	require.Equal(t, false, conjGroupTag.isSuperset(&ipBlockConj, emptyHints))
}
