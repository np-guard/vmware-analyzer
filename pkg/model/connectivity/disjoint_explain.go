package connectivity

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/common"
)

type containmentRes int

const (
	disjoint containmentRes = 0
	subset   containmentRes = 1
	superset containmentRes = 2
	equal    containmentRes = 3
	overlap  containmentRes = 4
)

func connectionsContainmentResult(c1, c2 *netset.TransportSet) containmentRes {
	if c1.Equal(c2) {
		return equal
	}
	if c1.IsSubset(c2) {
		return subset
	}
	if c2.IsSubset(c1) {
		return superset
	}
	if c2.Intersect(c1).IsEmpty() {
		return disjoint
	}
	return overlap
}

func (c ConnMap) disjointConnComputePerEntry(entry *RuleAndConn, disjointConnections []*netset.TransportSet) []*netset.TransportSet {
	toAdd := true // toAdd marks if this entry should be added as a disjoint connection
	disjointConnectionsTransformed := []*netset.TransportSet{}
	currentConn := entry.Conn
	for _, d := range disjointConnections {
		switch connectionsContainmentResult(currentConn, d) {
		case equal:
			disjointConnectionsTransformed = append(disjointConnectionsTransformed, d)
			toAdd = false
			continue
		case disjoint:
			disjointConnectionsTransformed = append(disjointConnectionsTransformed, d)
			// toAdd remains true
			continue
		case superset:
			disjointConnectionsTransformed = append(disjointConnectionsTransformed, d)
			currentConn = currentConn.Subtract(d)
			// toAdd remains true
		case subset:
			disjointConnectionsTransformed = append(disjointConnectionsTransformed, d.Subtract(currentConn))
			// toAdd remains true
		case overlap:
			disjointConnectionsTransformed = append(disjointConnectionsTransformed, d.Subtract(currentConn))
			currentConn = currentConn.Subtract(d)
			// toAdd remains true
		}
	}
	if toAdd {
		disjointConnectionsTransformed = append(disjointConnectionsTransformed, currentConn)
	}
	// override disjointConnections
	disjointConnections = slices.Clone(disjointConnectionsTransformed)
	return disjointConnections
}

func (c ConnMap) GetDisjointConnecionSetsPerExplanationsForEndpoints(srcVM, dstVM string) []*netset.TransportSet {
	entry := c.getEntryPerEndpoints(srcVM, dstVM)
	if entry == nil {
		return nil
	}
	disjointConnections := []*netset.TransportSet{} // elements in this slice should always be disjoint
	for _, egressEntry := range entry.DetailedConn.ExplanationObj.EgressExplanations {
		disjointConnections = c.disjointConnComputePerEntry(egressEntry, disjointConnections)
	}
	for _, ingressEntry := range entry.DetailedConn.ExplanationObj.IngressExplanations {
		disjointConnections = c.disjointConnComputePerEntry(ingressEntry, disjointConnections)
	}
	return disjointConnections
}

// GetDisjointExplanationsPerEndpoints returns the list of connections disjoint by explanations content
func (c ConnMap) GetDisjointExplanationsPerEndpoints(srcVM, dstVM string) (allowed, denied []*DetailedConnection) {
	entry := c.getEntryPerEndpoints(srcVM, dstVM)
	if entry == nil {
		return nil, nil
	}
	disjointConns := c.GetDisjointConnecionSetsPerExplanationsForEndpoints(srcVM, dstVM)
	// for each disjointConnections, should now collect its relevant explanations ingress and egress

	for _, conn := range disjointConns {
		isAllowed := conn.IsSubset(entry.DetailedConn.Conn)
		// add the relevant rules for each disjoint conn
		connExplanation := &DetailedConnection{Conn: conn}
		connExplanation.ExplanationObj = &Explanation{}
		for _, egressExp := range entry.DetailedConn.ExplanationObj.EgressExplanations {
			if conn.IsSubset(egressExp.Conn) {
				connExplanation.ExplanationObj.EgressExplanations = append(connExplanation.ExplanationObj.EgressExplanations, egressExp)
			}
		}
		for _, ingressExp := range entry.DetailedConn.ExplanationObj.IngressExplanations {
			if conn.IsSubset(ingressExp.Conn) {
				connExplanation.ExplanationObj.IngressExplanations = append(connExplanation.ExplanationObj.IngressExplanations, ingressExp)
			}

		}
		if isAllowed {
			allowed = append(allowed, connExplanation)
		} else {
			denied = append(denied, connExplanation)
		}
	}
	return allowed, denied
}

// todo: just for debugging for now
func PrintDisjointExplanations(allowed, denied []*DetailedConnection) {
	fmt.Println("allowed disjoint explains:")
	for _, a := range allowed {
		fmt.Printf("conn: %s, ingress rules: %s, egress rules: %s\n", a.Conn.String(),
			common.JoinCustomStrFuncSlice(a.ExplanationObj.IngressExplanations, func(s *RuleAndConn) string { return fmt.Sprintf("%d", s.RuleID) }, " ; "),
			common.JoinCustomStrFuncSlice(a.ExplanationObj.EgressExplanations, func(s *RuleAndConn) string { return fmt.Sprintf("%d", s.RuleID) }, " ; "),
		)
	}
	fmt.Println("denied disjoint explains:")
	for _, a := range denied {
		fmt.Printf("conn: %s, ingress rules: %s, egress rules: %s\n", a.Conn.String(),
			common.JoinCustomStrFuncSlice(a.ExplanationObj.IngressExplanations, func(s *RuleAndConn) string { return fmt.Sprintf("%d", s.RuleID) }, " ; "),
			common.JoinCustomStrFuncSlice(a.ExplanationObj.EgressExplanations, func(s *RuleAndConn) string { return fmt.Sprintf("%d", s.RuleID) }, " ; "),
		)
	}
}
