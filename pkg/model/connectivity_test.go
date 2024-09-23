package model

import (
	"fmt"
	"testing"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	"github.com/stretchr/testify/require"
)

// simple set of VMs for basic test
var vmA = endpoints.NewVM("A")
var vmB = endpoints.NewVM("B")
var vmC = endpoints.NewVM("C")
var allVms = []*endpoints.VM{vmA, vmB, vmC}

var dfwA = dfw.NewEmptyDFW(false) // no rules and global default deny

// basic test
var config1 = &config{
	vms: allVms,
	fw:  dfwA,
}

func sumPairs(c connMap) int {
	res := 0
	for _, srcMap := range c {
		res += len(srcMap)
	}
	return res
}

func sumNoConns(c connMap) int {
	res := 0
	for _, srcMap := range c {
		for _, conn := range srcMap {
			if conn.IsEmpty() {
				res++
			}
		}
	}
	return res
}

func TestConnectivityBasicGlobalDefaultDeny(t *testing.T) {
	connRes := config1.getConnectivity()

	// all vm pairs (except of vm to itself) should be in the input connRes
	require.Equal(t, len(allVms)*(len(allVms)-1), sumPairs(connRes))

	// in this test, all entires are expecetd to be with No connections
	require.Equal(t, sumPairs(connRes), sumNoConns(connRes))

	fmt.Printf("%s", connRes.string())
	fmt.Println("done")
}
