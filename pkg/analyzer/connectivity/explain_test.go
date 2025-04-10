package connectivity

import (
	"fmt"
	"testing"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func newVM(name string) topology.Endpoint {
	return topology.NewVM(name, name)
}

// todo: improve test
func TestDisjointExplanationsPerEndpoints(t *testing.T) {
	vmA := newVM("A")
	vmB := newVM("B")
	ruleAndConn1 := &RuleAndConn{Conn: netset.AllTransports(), RuleID: 1}
	ruleAndConn2 := &RuleAndConn{Conn: netset.AllTCPTransport(), RuleID: 2}
	ruleAndConn3 := &RuleAndConn{Conn: netset.NewICMPTransport(8, 8, 0, 0), RuleID: 3}
	exp := &Explanation{IngressExplanations: []*RuleAndConn{ruleAndConn2}, EgressExplanations: []*RuleAndConn{ruleAndConn3, ruleAndConn1}}
	detailedConn := &DetailedConnection{Conn: netset.AllTransports(), ExplanationObj: exp}

	cmap := ConnMap{}
	cmap.InitPairs(false, []topology.Endpoint{vmA, vmB}, []topology.Endpoint{vmA, vmB}, nil)
	cmap.Add(vmA, vmB, detailedConn)

	res := cmap.GetDisjointConnecionSetsPerExplanationsForEndpoints(vmA.Name(), vmB.Name())
	fmt.Printf("res: %s", common.JoinStringifiedSlice(res, "\n"))

	fmt.Println("done")
}
