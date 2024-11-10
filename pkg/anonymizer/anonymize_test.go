/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type inter interface {
}

type structA struct {
	BAsStruct    structB
	BAsPointer   *structB
	BAsInterface inter
	BAsSlices    []structB
	Id           *string
	DisplayName  *string
	Path         *string
}
type structB struct {
	anInt       int
	aSlice      []int
	Id          *string
	OwnerId     *string
	OwnerVmId   *string
	DisplayName *string
	Path        *string
}

var uniqStringCounter = 0

func createUniqString() *string {
	uniqStringCounter++
	a := fmt.Sprintf("str%d", uniqStringCounter)
	return &a
}
func newStructB(OwnerId string) structB {
	Id := createUniqString()
	path := fmt.Sprintf("/As/%s/Bs/%s", OwnerId, *Id)

	return structB{aSlice: []int{6, 7},
		Id:          Id,
		DisplayName: createUniqString(),
		OwnerId:     &OwnerId,
		Path:        &path}
}
func newStructBPointer(OwnerId string) *structB {
	b := newStructB(OwnerId)
	return &b
}

func Test_anonymize(t *testing.T) {
	Id := createUniqString()
	path := fmt.Sprintf("/As/%s", *Id)
	sa := &structA{
		BAsStruct:    newStructB(*Id),
		BAsPointer:   newStructBPointer(*Id),
		BAsInterface: newStructBPointer(*Id),
		BAsSlices: []structB{
			newStructB(*Id),
			newStructB(*Id),
		},
		Id:          Id,
		DisplayName: createUniqString(),
		Path:        &path,
	}
	Anonymize(sa)
	saId := "structA.Id.10000"
	bId := "structA.Id.10003"
	require.Equal(t, saId, *sa.Id)
	require.Equal(t, saId, *sa.BAsPointer.OwnerId)
	require.Equal(t, saId, *sa.BAsStruct.OwnerId)
	require.Equal(t, bId, *sa.BAsSlices[0].Id)
	require.Equal(t, fmt.Sprintf("/As/%s/Bs/%s", saId, bId), *sa.BAsSlices[0].Path)
	require.Equal(t, (*string)(nil), sa.BAsSlices[1].OwnerVmId)
}
