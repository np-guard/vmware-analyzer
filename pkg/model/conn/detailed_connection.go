/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package conn

import (
	"github.com/np-guard/models/pkg/netset"
)

//////////////////////////////////////////////////////////////////////

type DetailedConnection struct {
	Conn        *netset.TransportSet
	explanation *Explanation
}

func NewDetailedConnection(conn *netset.TransportSet, explanations *Explanation) *DetailedConnection {
	return &DetailedConnection{Conn: conn, explanation: explanations}
}
func NewEmptyDetailedConnection() *DetailedConnection {
	return &DetailedConnection{Conn: netset.NoTransports(), explanation: &Explanation{}}
}
func NewAllDetailedConnection() *DetailedConnection {
	return &DetailedConnection{Conn: netset.AllTransports(), explanation: &Explanation{}}
}
func (d *DetailedConnection) Explanation() *Explanation {
	return d.explanation
}
func (d *DetailedConnection) String() string { return d.Conn.String() }

// ConnectivityExplanation has the explanation of specific connectivity:
// whether the connectivity allowed, and what are the rules that allow/deny it
type connectivityExplanation struct {
	Conn        *netset.TransportSet
	EgressRule  int
	IngressRule int
	Allow       bool
}

// currently, the explanation is a list of connectivityExplanation, each represent another connection
type Explanation struct {
	explanations []connectivityExplanation
}

func (es *Explanation) Explanations() []connectivityExplanation { return es.explanations }
func (es *Explanation) AddExplanation(conn *netset.TransportSet, egressRule, ingressRule int, allow bool) {
	es.explanations = append(es.explanations,
		connectivityExplanation{Conn: conn, EgressRule: egressRule, IngressRule: ingressRule, Allow: allow})
}
