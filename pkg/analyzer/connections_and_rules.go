package analyzer

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
)

type connectionsAndRules struct {
	accumulatedConns  *netset.TransportSet
	partitionsByRules []*connectivity.RuleAndConn
}

func emptyConnectionsAndRules() *connectionsAndRules {
	return &connectionsAndRules{
		accumulatedConns: netset.NoTransports(),
	}
}

func (cr *connectionsAndRules) union(cr2 *connectionsAndRules) {
	cr.accumulatedConns = cr.accumulatedConns.Union(cr2.accumulatedConns)
	cr.partitionsByRules = append(cr.partitionsByRules, cr2.partitionsByRules...)
}

func (cr *connectionsAndRules) String() string {
	partitionsByRulesStr := common.JoinStringifiedSlice(cr.partitionsByRules, ";")
	return fmt.Sprintf("accumulatedConns: %s, partitionsByRules: %s", cr.accumulatedConns.String(), partitionsByRulesStr)
}
