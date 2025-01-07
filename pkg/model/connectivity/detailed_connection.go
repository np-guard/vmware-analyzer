/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connectivity

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/common"
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
}

// RuleAndConn contains a set of connections and a rule ID which is directly related to these connections
type RuleAndConn struct {
	Conn   *netset.TransportSet
	RuleID int
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
	ingressExplanationsFiltered := filterExplanation(es.IngressExplanations, connSet)
	egressExplanationsFiltered := filterExplanation(es.EgressExplanations, connSet)

	ingress := common.JoinStringifiedSlice(ingressExplanationsFiltered, ",")
	egress := common.JoinStringifiedSlice(egressExplanationsFiltered, ",")

	return fmt.Sprintf("ingress: %s\negress: %s", ingress, egress)
}

func (es *Explanation) RuleIDsAsStrings(ids []int) []string {
	res := make([]string, len(ids))
	for i := range ids {
		res[i] = fmt.Sprintf("%d", ids[i])
	}
	return res
}

func (es *Explanation) RuleIDs() (ingress, egress []int) {
	ingress = make([]int, len(es.IngressExplanations))
	for _, ingressExp := range es.IngressExplanations {
		ingress = append(ingress, ingressExp.RuleID)
	}
	egress = make([]int, len(es.IngressExplanations))
	for _, egressExp := range es.EgressExplanations {
		egress = append(egress, egressExp.RuleID)
	}
	return ingress, egress
}

func (rac *RuleAndConn) String() string {
	return fmt.Sprintf("{conn: %s, ruleID: %d}", rac.Conn.String(), rac.RuleID)
}

func filterExplanation(allExplanations []*RuleAndConn, connSet *netset.TransportSet) []*RuleAndConn {
	res := []*RuleAndConn{}
	for _, r := range allExplanations {
		if r == nil {
			panic(r)
		}
		if !r.Conn.Intersect(connSet).IsEmpty() {
			res = append(res, &RuleAndConn{RuleID: r.RuleID, Conn: r.Conn.Intersect(connSet)})
		}
	}
	return res
}
