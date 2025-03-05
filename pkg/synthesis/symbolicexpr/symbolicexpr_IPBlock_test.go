package symbolicexpr

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func getIPBlocksTerms() (allIpBlockTerm, ipBlockTerm1, ipBlockTerm2, ipBlockTerm3, ipAddrSingleTerm *ipBlockAtomicTerm) {
	allIPBlock, _ := netset.IPBlockFromCidr("0.0.0.0/0")
	ipBlock1, _ := netset.IPBlockFromCidr("1.2.3.0/8")
	ipBlock2, _ := netset.IPBlockFromCidr("1.2.3.0/16")
	ipBlock3, _ := netset.IPBlockFromCidr("192.0.2.0/24")
	ipAddrSingle, _ := netset.IPBlockFromCidr("192.0.2.0/32")
	allIpBlockTerm = NewIPBlockTermTerm(&topology.IpBlock{Block: allIPBlock, OriginalIP: "0.0.0.0/0"})
	ipBlockTerm1 = NewIPBlockTermTerm(&topology.IpBlock{Block: ipBlock1, OriginalIP: "1.2.3.0/8"})
	ipBlockTerm2 = NewIPBlockTermTerm(&topology.IpBlock{Block: ipBlock2, OriginalIP: "1.2.3.0/16"})
	ipBlockTerm3 = NewIPBlockTermTerm(&topology.IpBlock{Block: ipBlock3, OriginalIP: "192.0.2.0/24"})
	ipAddrSingleTerm = NewIPBlockTermTerm(&topology.IpBlock{Block: ipAddrSingle, OriginalIP: "192.0.2.0 originalIP"})
	return
}

func TestIpBlockTerm(t *testing.T) {
	allIpBlockTerm, ipBlockTerm1, ipBlockTerm2, ipBlockTerm3, ipAddrSingleTerm := getIPBlocksTerms()
	fmt.Println("allIpBlockTerm is", allIpBlockTerm)
	fmt.Println("ipBlockTerm1 is", ipBlockTerm1)
	fmt.Println("ipBlockTerm2 is", ipBlockTerm2)
	fmt.Println("ipBlockTerm3 is", ipBlockTerm3)
	fmt.Println("ipAddrSingleTerm is", ipAddrSingleTerm)

	// tests String and Name
	require.Equal(t, "IP addr in 0.0.0.0/0", allIpBlockTerm.String())
	require.Equal(t, "IP addr in 192.0.2.0/24", ipBlockTerm3.String())
	require.Equal(t, "IP addr in 192.0.2.0 originalIP", ipAddrSingleTerm.String())

	// tests IsTautology()
	require.Equal(t, true, allIpBlockTerm.IsTautology(), "0.0.0.0/0 is a tautology")
	require.Equal(t, false, ipBlockTerm1.IsTautology(), "1.2.3.0/8 is not a tautology")
	require.Equal(t, false, ipAddrSingleTerm.IsTautology(), "192.0.2.0 is not a tautology")

	// tests negation String()
	fmt.Println("neg ipBlockTerm3 is", ipBlockTerm3.negate())
	fmt.Println("neg ipAddrSingleTerm is", ipAddrSingleTerm.negate())
	require.Equal(t, "IP addr not in 192.0.2.0/24", ipBlockTerm3.negate().String())
	require.Equal(t, "IP addr not in 192.0.2.0 originalIP", ipAddrSingleTerm.negate().String())

	// tests isNegateOf
	require.Equal(t, true, ipAddrSingleTerm.negate().isNegateOf(ipAddrSingleTerm),
		"negation is isNegateOf under term with OriginalIP")
	require.Equal(t, true, ipBlockTerm1.negate().isNegateOf(ipBlockTerm1), "negation is isNegateOf")
	require.Equal(t, true, allIpBlockTerm.negate().isNegateOf(allIpBlockTerm),
		"negation is isNegateOf also for 0.0.0.0/0 which negation is empty set")
	require.Equal(t, false, ipBlockTerm1.isNegateOf(ipAddrSingleTerm), "disjoint blocks are not "+
		"negation of each other")
	require.Equal(t, false, allIpBlockTerm.isNegateOf(ipAddrSingleTerm), "blocks with containment "+
		"relations are not negation of each other")
	require.Equal(t, false, ipBlockTerm2.isNegateOf(ipBlockTerm3), "blocks with containment "+
		"relations are not negation of each other")

	// tests disjoint
	require.Equal(t, true, ipAddrSingleTerm.disjoint(ipBlockTerm1, &Hints{}),
		"192.0.2.0 disjoint to 1.2.3.0/8")
	require.Equal(t, true, ipBlockTerm3.disjoint(ipBlockTerm1, &Hints{}),
		"192.0.2.0/24 disjoint to 1.2.3.0/8")
	require.Equal(t, false, ipBlockTerm2.disjoint(ipBlockTerm1, &Hints{}),
		"1.2.3.0/16 not disjoint to 1.2.3.0/8")
	require.Equal(t, false, ipBlockTerm2.disjoint(allIpBlockTerm, &Hints{}),
		"1.2.3.0/16 not disjoint to 0.0.0.0/0")
	require.Equal(t, false, allIpBlockTerm.disjoint(ipBlockTerm1, &Hints{}),
		"0.0.0.0/0 not disjoint to 1.2.3.0/8")

	// tests supersetOf
	require.Equal(t, false, ipBlockTerm2.supersetOf(allIpBlockTerm, &Hints{}),
		"1.2.3.0/16 not superset of 0.0.0.0/0")
	require.Equal(t, true, allIpBlockTerm.supersetOf(ipBlockTerm1, &Hints{}),
		"0.0.0.0/0 superset of 1.2.3.0/8")
	require.Equal(t, true, ipBlockTerm1.supersetOf(ipBlockTerm2, &Hints{}),
		"1.2.3.0/8 superset of 1.2.3.0/16")
	require.Equal(t, false, ipBlockTerm2.supersetOf(ipBlockTerm1, &Hints{}),
		"1.2.3.0/16 not superset of 1.2.3.0/8")
	require.Equal(t, false, ipAddrSingleTerm.supersetOf(ipBlockTerm2, &Hints{}),
		"192.0.2.0 not superset of 1.2.3.0/16")
	require.Equal(t, true, ipAddrSingleTerm.supersetOf(ipAddrSingleTerm, &Hints{}),
		"addr superset of itself")
}

func TestIpBlockWithConj(t *testing.T) {
	allIpBlockTerm, ipBlockTerm1, ipBlockTerm2, ipBlockTerm3, ipAddrSingleTerm := getIPBlocksTerms()
	slytherin, gryffindor := "Slytherin", "Gryffindor"
	atomicSly := NewTagTerm(slytherin, false)
	atomicGry := NewTagTerm(gryffindor, false)
	conjAllIpBlockTermOnly := &Conjunction{allIpBlockTerm}
	conjIPBlockTerm1 := &Conjunction{ipBlockTerm1, atomicSly, atomicGry}
	conjIPBlockTerm2Only := &Conjunction{ipBlockTerm2}
	conjIPBlockTerm3 := &Conjunction{ipBlockTerm3, atomicSly, atomicGry}
	conjIPAddrSingleTerm := &Conjunction{ipAddrSingleTerm, atomicSly, atomicGry}
	fmt.Println("conjAllIpBlockTerm is", conjAllIpBlockTermOnly)
	fmt.Println("conjIPBlockTerm1 is", conjIPBlockTerm1)
	fmt.Println("conjIPBlockTerm2 is", conjIPBlockTerm2Only)
	fmt.Println("conjIPBlockTerm3 is", conjIPBlockTerm3)
	fmt.Println("conjIPAddrSingleTerm is", conjIPAddrSingleTerm)
	fmt.Println()

	// tests add
	term2AddTerm3 := conjIPBlockTerm2Only.add(ipBlockTerm3)
	allAddTerm3 := conjAllIpBlockTermOnly.add(ipBlockTerm3)
	singleAddTerm3 := conjIPAddrSingleTerm.add(ipBlockTerm3)
	term3AddSingle := conjIPBlockTerm3.add(ipAddrSingleTerm)
	term1AddTerm3 := conjIPBlockTerm1.add(ipBlockTerm3)
	term1AddTerm2 := conjIPBlockTerm1.add(ipBlockTerm2)

	fmt.Println("conjIPBlockTerm2.add(ipBlockTerm3)", term2AddTerm3)
	fmt.Println("conjAllIpBlockTerm.add(ipBlockTerm3)", allAddTerm3)
	fmt.Println("conjIPAddrSingleTerm.add(conjIPBlockTerm1)", singleAddTerm3)
	fmt.Println("conjIPBlockTerm3.add(ipAddrSingleTerm)", term3AddSingle)
	fmt.Println("conjIPBlockTerm1.add(ipBlockTerm3)", term1AddTerm3)
	fmt.Println("conjIPBlockTerm1.add(ipBlockTerm2)", term1AddTerm2)

	require.Equal(t, "(IP addr in the empty block)", term2AddTerm3.String())
	require.Equal(t, "(IP addr in 192.0.2.0/24)", allAddTerm3.String())
	require.Equal(t, "(IP addr in 192.0.2.0 originalIP and tag = Slytherin and tag = Gryffindor)",
		singleAddTerm3.String())
	require.Equal(t, "(IP addr in 192.0.2.0 and tag = Slytherin and tag = Gryffindor)",
		term3AddSingle.String())
	require.Equal(t, "(IP addr in the empty block and tag = Slytherin and tag = Gryffindor)",
		term1AddTerm3.String())
	require.Equal(t, "(IP addr in 1.2.0.0/16 and tag = Slytherin and tag = Gryffindor)",
		term1AddTerm2.String())

	// tests isFalse
	require.Equal(t, true, conjIPBlockTerm2Only.add(ipBlockTerm3).isFalse(&Hints{}),
		"1.2.3.0/16 intersected with 192.0.2.0/24 is empty (false)")
	require.Equal(t, false, conjAllIpBlockTermOnly.add(ipBlockTerm3).isFalse(&Hints{}),
		"0.0.0.0/0 intersected with 192.0.2.0/24 is not empty")
	require.Equal(t, false, conjIPBlockTerm3.add(ipAddrSingleTerm).isFalse(&Hints{}),
		"192.0.2.0/24 intersected with 192.0.2.0 is not empty")
	require.Equal(t, true, conjIPBlockTerm1.add(ipBlockTerm3).isFalse(&Hints{}),
		"1.2.3.0/8 intersected with 192.0.2.0/24 is empty")

	// test isTautology
	require.Equal(t, true, conjAllIpBlockTermOnly.isTautology(), "1.2.3.0/16 is tautology")
	require.Equal(t, false, conjAllIpBlockTermOnly.add(atomicSly).isTautology(), "adding a "+
		"non tautology block to 0.0.0.0/0 is not a tautology")
	require.Equal(t, false, conjIPBlockTerm2Only.isTautology(), "1.2.3.0/16 with OriginalIP not tautology")
	require.Equal(t, false, conjIPBlockTerm3.isTautology(), "192.0.2.0/24 not tautology")

	// test contains
	require.Equal(t, true, conjIPBlockTerm2Only.contains(ipBlockTerm2), "ip block implies itself")
	require.Equal(t, true, conjIPBlockTerm2Only.contains(ipBlockTerm1), "1.2.3.0/16 implies 1.2.3.0/16")
	require.Equal(t, true, conjIPBlockTerm2Only.contains(allIpBlockTerm), "1.2.3.0/16 implies 0.0.0.0/0")
	require.Equal(t, true, conjIPBlockTerm3.contains(allIpBlockTerm),
		"conj with ipBlock and other terms implies 0.0.0.0/0")
	require.Equal(t, true, conjIPAddrSingleTerm.contains(ipBlockTerm3),
		"conj with 192.0.2.0 implies 192.0.2.0/24")
	require.Equal(t, true, singleAddTerm3.contains(ipBlockTerm3),
		"result of add to conj with only ip addr implies its conj ip term")
	require.Equal(t, true, singleAddTerm3.contains(ipAddrSingleTerm),
		"result of add to conj with only ip addr implies its right term")
	require.Equal(t, true, term2AddTerm3.contains(ipBlockTerm1),
		"result of add to conj with not only ip addr implies its conj ip term")
	require.Equal(t, true, term1AddTerm3.contains(ipBlockTerm2),
		"result of add to conj with no only ip addr implies its right term")

	require.Equal(t, false, conjIPBlockTerm1.contains(ipBlockTerm2), "conj with 1.2.3.0/8 does not "+
		"imply 1.2.3.0/16")
	require.Equal(t, false, conjAllIpBlockTermOnly.contains(ipBlockTerm3), "conj with 0.0.0.0/0 does not "+
		"imply non 0.0.0.0/0 ip term")
}
