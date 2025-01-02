package model

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/model/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

func newVM(name string) *endpoints.VM {
	return endpoints.NewVM(name, name)
}

// simple set of VMs for basic test
var vmA = newVM("A")
var vmB = newVM("B")
var vmC = newVM("C")
var allVms = []*endpoints.VM{vmA, vmB, vmC}

var dfwAllowNothingByDefault = dfw.NewEmptyDFW(false) // no rules and global default deny
var dfwAllowAllByDefault = dfw.NewEmptyDFW(true)      // no rules and global default allow

// basic test
var config1 = &config{
	vms: allVms,
	fw:  dfwAllowNothingByDefault,
}

var config2 = &config{
	vms: allVms,
	fw:  dfwAllowAllByDefault,
}

func sumPairs(c connectivity.ConnMap) int {
	res := 0
	for _, srcMap := range c {
		res += len(srcMap)
	}
	return res
}

func sumNoConns(c connectivity.ConnMap) int {
	res := 0
	for _, srcMap := range c {
		for _, dDonn := range srcMap {
			if dDonn.Conn.IsEmpty() {
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
	res, err := conn1Res.GenTextualConnectivityOutput()
	require.Nil(t, err)
	fmt.Printf("%s\n", res)

	conn2Res := config2.getConnectivity()
	// all vm pairs (except of vm to itself) should be in the input connRes
	require.Equal(t, len(allVms)*(len(allVms)-1), sumPairs(conn2Res))
	// in this test, all entires are expecetd to be with No connections
	require.Equal(t, 0, sumNoConns(conn2Res))
	res, err = conn2Res.GenTextualConnectivityOutput()
	require.Nil(t, err)
	fmt.Printf("%s\n", res)

	fmt.Println("done")
}
