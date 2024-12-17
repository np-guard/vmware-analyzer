/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import "github.com/np-guard/models/pkg/netset"

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
