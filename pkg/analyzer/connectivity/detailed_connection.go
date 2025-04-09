/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connectivity

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

//////////////////////////////////////////////////////////////////////

// connectivity explanation types - context is between two specific endpoints

// DetailedConnection holds a connection set of permitted/blocked connections between two endpoints,
// and explanation object that holds the set of all rules reltaed to these connections
type DetailedConnection struct {
	Conn           *netset.TransportSet
	ExplanationObj *Explanation
}

// Explanation is composed of ingress and egress slices for rules and connections.
// a connection C from vm1 to vm2 is explained as follows:
// ingress: all rule IDs in IngressExplanations for which C is contained in the connection set object
// egress: all rule IDs in EgressExplanations for which C is contained in the connection set object
type Explanation struct {
	IngressExplanations []*RuleAndConn
	EgressExplanations  []*RuleAndConn

	NotDeterminedIngress *netset.TransportSet
	NotDeterminedEgress  *netset.TransportSet
}

// RuleAndConn contains a set of connections and a rule ID which is directly related to these connections
type RuleAndConn struct {
	Conn   *netset.TransportSet
	RuleID int
	Action dfw.RuleAction
}

//////////////////////////////////////////////////////////////////////

func NewDetailedConnection(conn *netset.TransportSet, explanations *Explanation) *DetailedConnection {
	return &DetailedConnection{Conn: conn, ExplanationObj: explanations}
}
func NewEmptyDetailedConnection() *DetailedConnection {
	return &DetailedConnection{Conn: netset.NoTransports(), ExplanationObj: &Explanation{}}
}
func NewAllDetailedConnection() *DetailedConnection {
	return &DetailedConnection{Conn: netset.AllTransports(), ExplanationObj: &Explanation{}}
}

func (d *DetailedConnection) DetailedExplanationString(connSet *netset.TransportSet) string {
	return d.ExplanationObj.String(connSet)
}

func (es *Explanation) String(connSet *netset.TransportSet) string {
	ingressExplanationsFiltered := FilterExplanation(es.IngressExplanations, connSet)
	egressExplanationsFiltered := FilterExplanation(es.EgressExplanations, connSet)

	ingress := common.JoinStringifiedSlice(ingressExplanationsFiltered, common.CommaSeparator)
	egress := common.JoinStringifiedSlice(egressExplanationsFiltered, common.CommaSeparator)

	return fmt.Sprintf("ingress: %s\negress: %s", ingress, egress)
}

func (es *Explanation) RuleIDs() (ingress, egress []int) {
	ingress = make([]int, len(es.IngressExplanations))
	for i := range es.IngressExplanations {
		ingress[i] = es.IngressExplanations[i].RuleID
	}
	egress = make([]int, len(es.EgressExplanations))
	for i := range es.EgressExplanations {
		egress[i] = es.EgressExplanations[i].RuleID
	}
	return ingress, egress
}

func (rac *RuleAndConn) String() string {
	return fmt.Sprintf("{conn: %s, ruleID: %d, action: %s}", rac.Conn.String(), rac.RuleID, rac.Action)
}

func FilterExplanation(allExplanations []*RuleAndConn, connSet *netset.TransportSet) []*RuleAndConn {
	res := []*RuleAndConn{}
	for _, r := range allExplanations {
		if r == nil {
			logging.InternalErrorf("unexpected nil entry in allExplanations []*RuleAndConn")
		}
		if !r.Conn.Intersect(connSet).IsEmpty() {
			res = append(res, &RuleAndConn{RuleID: r.RuleID, Conn: r.Conn.Intersect(connSet), Action: r.Action})
		}
	}
	return res
}
