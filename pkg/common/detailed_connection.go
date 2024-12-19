/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/np-guard/models/pkg/netset"
)

type DetailedConnection struct {
	Conn         *netset.TransportSet
	explanations []ConnectivityExplanation
}

func NewDetailedConnection(conn *netset.TransportSet) *DetailedConnection {
	return &DetailedConnection{Conn: conn}
}
func NewEmptyDetailedConnection() *DetailedConnection {
	return &DetailedConnection{Conn: netset.NoTransports()}
}
func NewAllDetailedConnection() *DetailedConnection {
	return &DetailedConnection{Conn: netset.AllTransports()}
}
func (d *DetailedConnection) AddExplanation(conn *netset.TransportSet, egressRule, ingressRule int, allow bool) {
	d.explanations = append(d.explanations, ConnectivityExplanation{Conn: conn, EgressRule: egressRule, IngressRule: ingressRule, Allow: allow})
}
func (d *DetailedConnection) Explanations() []ConnectivityExplanation {
	return d.explanations
}
func (d *DetailedConnection) String() string { return d.Conn.String() }

// ConnectivityExplaination has the explanation of specific connectivity:
// whether the connectivity allowed, and what are the rules that allow/deny it
type ConnectivityExplanation struct {
	Conn        *netset.TransportSet
	EgressRule  int
	IngressRule int
	Allow       bool
}
