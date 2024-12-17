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
}
type DetailedConnection struct {
	Conn      *netset.TransportSet
	ConnAllow []RuleConnectivity
	ConnDeny  []RuleConnectivity
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

func (d *DetailedConnection)String() string{
	res := fmt.Sprintf("allow: %s\ndeny: %s\n", d.Conn.String(), netset.AllTransports().Subtract( d.Conn).String())
	for _, c := range d.ConnAllow{
		res += fmt.Sprintf("    allow: %s %d,%d\n", c.Conn.String(), c.EgressRule,c.IngressRule)
	}
	for _, c := range d.ConnDeny{
		res += fmt.Sprintf("    deny: %s %d,%d\n", c.Conn.String(), c.EgressRule,c.IngressRule)
	}
	return res
}