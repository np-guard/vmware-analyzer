package model

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// simple set of VMs for basic test
var vmA = endpoints.NewVM("A")
var vmB = endpoints.NewVM("B")
var vmC = endpoints.NewVM("C")
var allVms = []*endpoints.VM{vmA, vmB, vmC}

var dfwAllowNothingByDefault = dfw.NewEmptyDFW(false) // no rules and global default deny
var dfwAllowAllByDefault = dfw.NewEmptyDFW(true)      // no rules and global default allow

// basic test
var config1 = &Config{
	vms: allVms,
	fw:  dfwAllowNothingByDefault,
}

var config2 = &Config{
	vms: allVms,
	fw:  dfwAllowAllByDefault,
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
	conn1Res := config1.getConnectivity()
	// all vm pairs (except of vm to itself) should be in the input connRes
	require.Equal(t, len(allVms)*(len(allVms)-1), sumPairs(conn1Res))
	// in this test, all entires are expecetd to be with No connections
	require.Equal(t, sumPairs(conn1Res), sumNoConns(conn1Res))
	fmt.Printf("%s\n", conn1Res.String())

	conn2Res := config2.getConnectivity()
	// all vm pairs (except of vm to itself) should be in the input connRes
	require.Equal(t, len(allVms)*(len(allVms)-1), sumPairs(conn2Res))
	// in this test, all entires are expecetd to be with No connections
	require.Equal(t, 0, sumNoConns(conn2Res))
	fmt.Printf("%s\n", conn2Res.String())

	fmt.Println("done")
}
