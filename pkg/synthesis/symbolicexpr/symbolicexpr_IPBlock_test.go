package symbolicexpr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func getIPBlocksTerms() (allIPBlockTerm *tautology, ipBlockTerm1, ipBlockTerm2, ipBlockTerm3, ipAddrSingleTerm *externalIPTerm) {
	ipBlock1, _ := netset.IPBlockFromCidr("1.2.3.0/8")
	ipBlock2, _ := netset.IPBlockFromCidr("1.2.3.0/16")
	ipBlock3, _ := netset.IPBlockFromCidr("192.0.2.0/24")
	ipAddrSingle, _ := netset.IPBlockFromCidr("192.0.2.0/32")
	allIPBlockTerm = &tautology{}
	ipBlockTerm1 = NewIPBlockTerm(&topology.IPBlock{Block: ipBlock1, OriginalIP: "1.2.3.0/8"})
	ipBlockTerm2 = NewIPBlockTerm(&topology.IPBlock{Block: ipBlock2, OriginalIP: "1.2.3.0/16"})
	ipBlockTerm3 = NewIPBlockTerm(&topology.IPBlock{Block: ipBlock3, OriginalIP: "192.0.2.0/24"})
	ipAddrSingleTerm = NewIPBlockTerm(&topology.IPBlock{Block: ipAddrSingle, OriginalIP: "192.0.2.0 originalIP"})
	return
}

func TestIpBlockTerm(t *testing.T) {
	allIPBlockTautology, ipBlockTerm1, ipBlockTerm2, ipBlockTerm3, ipAddrSingleTerm := getIPBlocksTerms()
	fmt.Println("allIPBlockTautology is", allIPBlockTautology)
	fmt.Println("ipBlockTerm1 is", ipBlockTerm1)
	fmt.Println("ipBlockTerm2 is", ipBlockTerm2)
	fmt.Println("ipBlockTerm3 is", ipBlockTerm3)
	fmt.Println("ipAddrSingleTerm is", ipAddrSingleTerm)

	// tests String and Name
	require.Equal(t, "IP addr in 0.0.0.0/0", allIPBlockTautology.String())
	require.Equal(t, "IP addr in 192.0.2.0/24", ipBlockTerm3.String())
	require.Equal(t, "IP addr in 192.0.2.0 originalIP", ipAddrSingleTerm.String())

	// tests IsTautology()
	require.Equal(t, true, allIPBlockTautology.IsTautology(), "0.0.0.0/0 is a tautology")
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
	require.Equal(t, true, allIPBlockTautology.negate().isNegateOf(allIPBlockTautology),
		"negation is isNegateOf also for 0.0.0.0/0 which negation is empty set")
	require.Equal(t, false, ipBlockTerm1.isNegateOf(ipAddrSingleTerm), "disjoint blocks are not "+
		"negation of each other")
	require.Equal(t, false, allIPBlockTautology.isNegateOf(ipAddrSingleTerm), "blocks with containment "+
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
	require.Equal(t, false, ipBlockTerm2.disjoint(allIPBlockTautology, &Hints{}),
		"1.2.3.0/16 not disjoint to 0.0.0.0/0")
	require.Equal(t, false, allIPBlockTautology.disjoint(ipBlockTerm1, &Hints{}),
		"0.0.0.0/0 not disjoint to 1.2.3.0/8")

	// tests supersetOf
	require.Equal(t, false, ipBlockTerm2.supersetOf(allIPBlockTautology, &Hints{}),
		"1.2.3.0/16 not superset of 0.0.0.0/0")
	require.Equal(t, true, allIPBlockTautology.supersetOf(ipBlockTerm1, &Hints{}),
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
	allIPBlockTautology, ipBlockTerm1, ipBlockTerm2, ipBlockTerm3, ipAddrSingleTerm := getIPBlocksTerms()
	conjAllIPBlockTermOnly := &Conjunction{allIPBlockTautology}
	conjIPBlockTerm1 := &Conjunction{ipBlockTerm1}
	conjIPBlockTerm2Only := &Conjunction{ipBlockTerm2}
	conjIPBlockTerm3 := &Conjunction{ipBlockTerm3}
	conjIPAddrSingleTerm := &Conjunction{ipAddrSingleTerm}
	fmt.Println("conjAllIPBlockTermOnly is", conjAllIPBlockTermOnly)
	fmt.Println("conjIPBlockTerm1 is", conjIPBlockTerm1)
	fmt.Println("conjIPBlockTerm2 is", conjIPBlockTerm2Only)
	fmt.Println("conjIPBlockTerm3 is", conjIPBlockTerm3)
	fmt.Println("conjIPAddrSingleTerm is", conjIPAddrSingleTerm)
	fmt.Println()

	// tests add
	term2AddTerm3 := conjIPBlockTerm2Only.add(ipBlockTerm3)
	allAddTerm3 := conjAllIPBlockTermOnly.add(ipBlockTerm3)
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
	require.Equal(t, "(IP addr in 192.0.2.0 originalIP)",
		singleAddTerm3.String())
	require.Equal(t, "(IP addr in 192.0.2.0)",
		term3AddSingle.String())
	require.Equal(t, "(IP addr in the empty block)",
		term1AddTerm3.String())
	require.Equal(t, "(IP addr in 1.2.0.0/16)",
		term1AddTerm2.String())

	// tests isEmpty
	require.Equal(t, true, conjIPBlockTerm2Only.add(ipBlockTerm3).isEmpty(&Hints{}),
		"1.2.3.0/16 intersected with 192.0.2.0/24 is empty (false)")
	require.Equal(t, false, conjAllIPBlockTermOnly.add(ipBlockTerm3).isEmpty(&Hints{}),
		"0.0.0.0/0 intersected with 192.0.2.0/24 is not empty")
	require.Equal(t, false, conjIPBlockTerm3.add(ipAddrSingleTerm).isEmpty(&Hints{}),
		"192.0.2.0/24 intersected with 192.0.2.0 is not empty")
	require.Equal(t, true, conjIPBlockTerm1.add(ipBlockTerm3).isEmpty(&Hints{}),
		"1.2.3.0/8 intersected with 192.0.2.0/24 is empty")

	// test isTautologyOrAllGroups
	require.Equal(t, true, conjAllIPBlockTermOnly.isTautologyOrAllGroups(), "1.2.3.0/16 is tautology")
	require.Equal(t, false, conjAllIPBlockTermOnly.add(ipBlockTerm2).isTautologyOrAllGroups(), "adding a "+
		"non tautology block to 0.0.0.0/0 is not a tautology")
	require.Equal(t, false, conjIPBlockTerm2Only.isTautologyOrAllGroups(), "1.2.3.0/16 with OriginalIP not tautology")
	require.Equal(t, false, conjIPBlockTerm3.isTautologyOrAllGroups(), "192.0.2.0/24 not tautology")

	// test contains
	require.Equal(t, true, conjIPBlockTerm2Only.contains(ipBlockTerm2), "ip block implies itself")
	require.Equal(t, true, conjIPBlockTerm2Only.contains(ipBlockTerm1), "1.2.3.0/16 implies 1.2.3.0/16")
	require.Equal(t, true, conjIPBlockTerm2Only.contains(allIPBlockTautology), "1.2.3.0/16 implies 0.0.0.0/0")
	require.Equal(t, true, conjIPBlockTerm3.contains(allIPBlockTautology),
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
	require.Equal(t, false, conjAllIPBlockTermOnly.contains(ipBlockTerm3), "conj with 0.0.0.0/0 does not "+
		"imply non 0.0.0.0/0 ip term")
}

func TestInternalIPTerms(t *testing.T) {
	ipInternal1, _ := netset.IPBlockFromCidr("172.16.0.0/12")
	ipInternal2, _ := netset.IPBlockFromCidr("192.168.0.0/16")
	ruleIPInternal1 := &topology.RuleIPBlock{IPBlock: topology.IPBlock{Block: ipInternal1, OriginalIP: "172.16.0.0/12"}}
	ruleIPInternal2 := &topology.RuleIPBlock{IPBlock: topology.IPBlock{Block: ipInternal2, OriginalIP: "192.168.0.0/16"}}
	ipInternalTerm1 := NewInternalIPTerm(ruleIPInternal1)
	ipInternalTerm2 := NewInternalIPTerm(ruleIPInternal2)
	internalIPTerm1Neg := ipInternalTerm1.negate()
	internalIPTerm2Neg := ipInternalTerm2.negate()
	fmt.Println("ipInternalTerm1 is", ipInternalTerm1.String())
	fmt.Println("ipInternalTerm2 is", ipInternalTerm2.String())
	fmt.Println("internalIPTerm1Neg is", internalIPTerm1Neg.String())
	fmt.Println("internalIPTerm2Neg is", internalIPTerm2Neg.String())
	disjoint := [][]string{{ipInternalTerm1.name(), ipInternalTerm2.name()}}
	hints := Hints{GroupsDisjoint: disjoint}
	// test disjoint between atomics with and without hints
	// with hints
	require.Equal(t, true, ipInternalTerm2.disjoint(ipInternalTerm1, &hints),
		"172.16.0.0/12 and 192.168.0.0/16 should be disjoint")
	require.Equal(t, false, internalIPTerm1Neg.disjoint(internalIPTerm2Neg, &hints),
		"Neg 172.16.0.0/12 and Neg 192.168.0.0/16 should not be disjoint")
	require.Equal(t, false, ipInternalTerm2.disjoint(internalIPTerm1Neg, &hints),
		"172.16.0.0/12 and Neg 192.168.0.0/16 should not be disjoint")
	// test supersetOf between atomics
	require.Equal(t, false, ipInternalTerm2.supersetOf(ipInternalTerm1, &hints),
		"192.168.0.0/16 not supersetOf 172.16.0.0/12")
	require.Equal(t, false, internalIPTerm1Neg.supersetOf(internalIPTerm2Neg, &hints),
		"Neg 192.168.0.0/16 not supersetOf Neg 172.16.0.0/12  should be disjoint")
	require.Equal(t, true, internalIPTerm1Neg.supersetOf(ipInternalTerm2, &hints),
		"172.16.0.0/12 neg supersetOf 192.168.0.0/16")
	require.Equal(t, true, internalIPTerm2Neg.supersetOf(ipInternalTerm1, &hints),
		"192.168.0.0/16 neg supersetOf 172.16.0.0/12")
	// without hints
	require.Equal(t, true, ipInternalTerm2.disjoint(ipInternalTerm1, &Hints{GroupsDisjoint: [][]string{}}),
		"172.16.0.0/12 and 192.168.0.0/16 should be disjoint")
	require.Equal(t, true, internalIPTerm1Neg.supersetOf(ipInternalTerm2, &Hints{GroupsDisjoint: [][]string{}}),
		"172.16.0.0/12 neg supersetOf 192.168.0.0/16")
	require.Equal(t, true, internalIPTerm2Neg.supersetOf(ipInternalTerm1, &Hints{GroupsDisjoint: [][]string{}}),
		"192.168.0.0/16 neg supersetOf 172.16.0.0/12")
}

func TestProcessTautologyWithExternals(t *testing.T) {
	// tautology with external terms
	allIPBlockTautology, ipBlockTerm1, ipBlockTerm2, _, _ := getIPBlocksTerms()
	Conjunction1 := Conjunction{ipBlockTerm1, allIPBlockTautology}
	Conj1AfterProcess := Conjunction1.processTautology(true)
	fmt.Printf("Conjunction1 is %v\n", Conjunction1.String())
	fmt.Printf("Conjunction1 after processTautology is\n%v\n\n", str(Conj1AfterProcess))
	require.Equal(t, 2, len(Conj1AfterProcess))
	require.Equal(t, true, Conj1AfterProcess[0].hasExternalIPBlockTerm())
	require.Equal(t, true, Conj1AfterProcess[1].isAllGroup())

	Conjunction2 := Conjunction{allIPBlockTautology, ipBlockTerm1}
	Conj2AfterProcess := Conjunction2.processTautology(true)
	fmt.Printf("Conjunction2 is %v\n", Conjunction2.String())
	fmt.Printf("Conjunction2 after processTautology is\n%v\n\n", str(Conj2AfterProcess))
	require.Equal(t, 2, len(Conj2AfterProcess))
	require.Equal(t, true, Conj2AfterProcess[0].hasExternalIPBlockTerm())
	require.Equal(t, true, Conj2AfterProcess[1].isAllGroup())

	Conjunction3 := Conjunction{ipBlockTerm2, allIPBlockTautology, ipBlockTerm1}
	Conj3AfterProcess := Conjunction3.processTautology(true)
	fmt.Printf("Conjunction3 is %v\n", Conjunction3.String())
	fmt.Printf("Conjunction3 after processTautology is\n%v\n\n", str(Conj3AfterProcess))
	require.Equal(t, 2, len(Conj3AfterProcess))
	require.Equal(t, true, Conj3AfterProcess[0].hasExternalIPBlockTerm())
	require.Equal(t, true, Conj3AfterProcess[1].isAllGroup())

	Conjunction4 := Conjunction{ipBlockTerm2, ipBlockTerm1}
	Conj4AfterProcess := Conjunction4.processTautology(true)
	fmt.Printf("Conjunction4 is %v\n\n", Conjunction4.String())
	fmt.Printf("Conjunction4 after processTautology is\n%v\n\n", str(Conj4AfterProcess))
	require.Equal(t, 1, len(Conj4AfterProcess))
	require.Equal(t, true, Conj4AfterProcess[0].hasExternalIPBlockTerm())
	require.Equal(t, false, Conj4AfterProcess[0].isAllGroup())
}

func str(cs []*Conjunction) string {
	res := make([]string, len(cs))
	for i, conj := range cs {
		res[i] = conj.String()
	}
	return strings.Join(res, "\n")
}
