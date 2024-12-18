/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
)

type RuleConnectivity struct {
	Conn        *netset.TransportSet
	EgressRule  int
	IngressRule int
	Allow       bool
}
type DetailedConnection struct {
	Conn      *netset.TransportSet
	RuleConns []RuleConnectivity
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
func (d *DetailedConnection) AddRuleConn(conn *netset.TransportSet, egressRule, ingressRule int, allow bool) {
	d.RuleConns = append(d.RuleConns, RuleConnectivity{Conn: conn, EgressRule: egressRule, IngressRule: ingressRule, Allow: allow})
}

func (d *DetailedConnection) String() string {
	res := fmt.Sprintf("allow: %s\ndeny: %s\n", d.Conn.String(), netset.AllTransports().Subtract(d.Conn).String())
	for _, c := range d.RuleConns {
		isAllowStr := "allow"
		if !c.Allow {
			isAllowStr = "deny"
		}
		res += fmt.Sprintf("    %s: %s %d,%d\n", isAllowStr, c.Conn.String(), c.EgressRule, c.IngressRule)
	}
	return res
}
