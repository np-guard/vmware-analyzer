/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import "github.com/np-guard/models/pkg/netset"
type DetailedConnection struct {
	Conn    *netset.TransportSet
	Explain []int
}
