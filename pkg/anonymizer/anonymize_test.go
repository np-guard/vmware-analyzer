/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"testing"
)

type inter interface {
	boo()
}

type structA struct {
	A            int
	BAsStruct    structB
	BAsPointer   *structB
	BAsInterface inter
	BAsSlices    []structB
	Id           *string
	DisplayName  *string
}
type structB struct {
	A           int
	Bs          []int
	Id          *string
	DisplayName *string
}

func (b *structB) boo() {}

var i = 0

func aString() *string {
	i++
	a := fmt.Sprintf("str%d", i)
	return &a
}
func Test_anonymize(_ *testing.T) {
	sa := &structA{
		A:            5,
		BAsStruct:    structB{A: 1, Bs: []int{6, 7}, Id: aString(), DisplayName: aString()},
		BAsPointer:   &structB{A: 2, Bs: []int{8, 9}, Id: aString(), DisplayName: aString()},
		BAsInterface: &structB{A: 3, Bs: []int{10, 11}, Id: aString(), DisplayName: aString()},
		BAsSlices: []structB{
			{A: 4, Bs: []int{12, 13}, Id: aString(), DisplayName: aString()},
			{A: 5, Bs: []int{14, 15}, Id: aString(), DisplayName: aString()},
		}, Id: aString(), DisplayName: aString(),
	}
	anonymize(sa)
}
