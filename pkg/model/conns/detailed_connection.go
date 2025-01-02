/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package conns

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/common"
)

//////////////////////////////////////////////////////////////////////

type DetailedConnection struct {
	Conn           *netset.TransportSet
	ExplanationObj *Explanation
}

func NewDetailedConnection(conn *netset.TransportSet, explanations *Explanation) *DetailedConnection {
	return &DetailedConnection{Conn: conn, ExplanationObj: explanations}
}
func NewEmptyDetailedConnection() *DetailedConnection {
	return &DetailedConnection{Conn: netset.NoTransports(), ExplanationObj: &Explanation{}}
}
func NewAllDetailedConnection() *DetailedConnection {
	return &DetailedConnection{Conn: netset.AllTransports(), ExplanationObj: &Explanation{}}
}
func (d *DetailedConnection) Explanation() *Explanation {
	return d.ExplanationObj
}
func (d *DetailedConnection) String() string {
	return d.Conn.String()
	//return fmt.Sprintf("%s %s", d.Conn.String(), d.ExplanationObj.String())
}
func (d *DetailedConnection) DetailedExplanationString(connSet *netset.TransportSet) string {
	ingress, egress := d.ExplanationObj.DetailsStr(connSet)
	return fmt.Sprintf("%s\n%s", ingress, egress)

}

// ConnectivityExplanation has the explanation of specific connectivity:
// whether the connectivity allowed, and what are the rules that allow/deny it
type ConnectivityExplanation struct {
	Conn        *netset.TransportSet
	EgressRule  int
	IngressRule int
	Allow       bool
}

func (ce ConnectivityExplanation) String() string {
	return fmt.Sprintf("conn: %s, egress rule: %d, ingress rule: %d, isAllow: %t", ce.Conn.String(), ce.EgressRule, ce.IngressRule, ce.Allow)
}

// currently, the explanation is a list of connectivityExplanation, each represent another connection
type Explanation struct {
	ExplanationsList    []ConnectivityExplanation
	CurrentExplainStr   string
	IngressExplanations []*RuleAndConn
	EgressExplanations  []*RuleAndConn
}

func (es *Explanation) Explanations() []ConnectivityExplanation { return es.ExplanationsList }
func (es *Explanation) AddExplanation(conn *netset.TransportSet, egressRule, ingressRule int, allow bool) {
	es.ExplanationsList = append(es.ExplanationsList,
		ConnectivityExplanation{Conn: conn, EgressRule: egressRule, IngressRule: ingressRule, Allow: allow})
}

func (es *Explanation) DetailsStr(connSet *netset.TransportSet) (ingress, egress string) {
	ingressExplanationsFiltered := filterExplanation(es.IngressExplanations, connSet)
	egressExplanationsFiltered := filterExplanation(es.EgressExplanations, connSet)

	ingress = common.JoinStringifiedSlice(ingressExplanationsFiltered, ",")
	egress = common.JoinStringifiedSlice(egressExplanationsFiltered, ",")

	return fmt.Sprintf("ingress: %s", ingress), fmt.Sprintf("egress: %s", egress)
}

func (es *Explanation) String() string {
	return es.CurrentExplainStr
}

type RuleAndConn struct {
	Conn *netset.TransportSet
	Rule int
}

func (rac *RuleAndConn) String() string {
	return fmt.Sprintf("{conn: %s, ruleID: %d}", rac.Conn.String(), rac.Rule)
}

func filterExplanation(allExplanations []*RuleAndConn, connSet *netset.TransportSet) []*RuleAndConn {
	res := []*RuleAndConn{}
	for _, r := range allExplanations {
		if r == nil {
			panic(r)
		}
		if !r.Conn.Intersect(connSet).IsEmpty() {
			res = append(res, &RuleAndConn{Rule: r.Rule, Conn: r.Conn.Intersect(connSet)})
		}
	}
	return res
}
