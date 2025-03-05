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
	require.Equal(t, true, allIpBlockTerm.IsTautology())
	require.Equal(t, false, ipBlockTerm1.IsTautology())
	require.Equal(t, false, ipAddrSingleTerm.IsTautology())

	// tests negation String()
	fmt.Println("neg ipBlockTerm3 is", ipBlockTerm3.negate())
	fmt.Println("neg ipAddrSingleTerm is", ipAddrSingleTerm.negate())
	require.Equal(t, "IP addr not in 192.0.2.0/24", ipBlockTerm3.negate().String())
	require.Equal(t, "IP addr not in 192.0.2.0 originalIP", ipAddrSingleTerm.negate().String())

	// tests isNegateOf
	require.Equal(t, true, ipAddrSingleTerm.negate().isNegateOf(ipAddrSingleTerm))
	require.Equal(t, true, ipBlockTerm1.negate().isNegateOf(ipBlockTerm1))
	require.Equal(t, true, allIpBlockTerm.negate().isNegateOf(allIpBlockTerm))
	require.Equal(t, false, ipBlockTerm1.isNegateOf(ipAddrSingleTerm))
	require.Equal(t, false, allIpBlockTerm.isNegateOf(ipAddrSingleTerm))
	require.Equal(t, false, ipBlockTerm2.isNegateOf(ipBlockTerm3))

	// tests disjoint
	require.Equal(t, true, ipAddrSingleTerm.disjoint(ipBlockTerm1, &Hints{}))
	require.Equal(t, true, ipBlockTerm3.disjoint(ipBlockTerm1, &Hints{}))
	require.Equal(t, false, ipBlockTerm2.disjoint(ipBlockTerm1, &Hints{}))
	require.Equal(t, false, ipBlockTerm2.disjoint(allIpBlockTerm, &Hints{}))
	require.Equal(t, false, allIpBlockTerm.disjoint(ipBlockTerm1, &Hints{}))

	// tests supersetOf
	require.Equal(t, false, ipBlockTerm2.supersetOf(allIpBlockTerm, &Hints{}))
	require.Equal(t, true, allIpBlockTerm.supersetOf(ipBlockTerm1, &Hints{}))
	require.Equal(t, true, ipBlockTerm1.supersetOf(ipBlockTerm2, &Hints{}))
	require.Equal(t, false, ipBlockTerm2.supersetOf(ipBlockTerm1, &Hints{}))
	require.Equal(t, false, ipAddrSingleTerm.supersetOf(ipBlockTerm2, &Hints{}))
	require.Equal(t, true, ipAddrSingleTerm.supersetOf(ipAddrSingleTerm, &Hints{}))
	require.Equal(t, true, allIpBlockTerm.supersetOf(allIpBlockTerm, &Hints{}))
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
	require.Equal(t, true, conjIPBlockTerm2Only.add(ipBlockTerm3).isFalse(&Hints{}))
	require.Equal(t, false, conjAllIpBlockTermOnly.add(ipBlockTerm3).isFalse(&Hints{}))
	require.Equal(t, false, conjIPBlockTerm3.add(ipAddrSingleTerm).isFalse(&Hints{}))
	require.Equal(t, true, conjIPBlockTerm1.add(ipBlockTerm3).isFalse(&Hints{}))

	// test isTautology
	require.Equal(t, true, conjAllIpBlockTermOnly.isTautology())
	require.Equal(t, false, conjAllIpBlockTermOnly.add(atomicSly).isTautology())
	require.Equal(t, false, conjIPBlockTerm2Only.isTautology())
	require.Equal(t, false, conjIPBlockTerm3.isTautology())
}
