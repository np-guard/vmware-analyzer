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

type structA struct {
	BAsStruct    structB
	BAsPointer   *structB
	BAsInterface interface{}
	BAsSlices    []structB
	Id           *string //nolint:stylecheck // names should be as in nsx_sdk.go
	DisplayName  *string
	Path         *string
}
type structB struct {
	aSlice      []int
	Id          *string //nolint:stylecheck // names should be as in nsx_sdk.go
	OwnerVmId   *string //nolint:stylecheck // names should be as in nsx_sdk.go
	TargetId    *string //nolint:stylecheck // names should be as in nsx_sdk.go
	DisplayName *string
	Path        *string
}

var uniqStringCounter = 0

func createUniqString() *string {
	uniqStringCounter++
	a := fmt.Sprintf("str%d", uniqStringCounter)
	return &a
}
func newStructB(ownerVMID string) structB {
	ID := createUniqString()
	path := fmt.Sprintf("/infra/As/%s/Bs/%s", ownerVMID, *ID)

	return structB{aSlice: []int{6, 7},
		Id:          ID,
		DisplayName: createUniqString(),
		OwnerVmId:   &ownerVMID,
		Path:        &path}
}
func newStructBPointer(ownerVMId string) *structB {
	b := newStructB(ownerVMId)
	return &b
}

func Test_anonymize(t *testing.T) {
	ID := createUniqString()
	path := fmt.Sprintf("/infra/As/%s", *ID)
	sa := &structA{
		BAsStruct:    newStructB(*ID),
		BAsPointer:   newStructBPointer(*ID),
		BAsInterface: newStructBPointer(*ID),
		BAsSlices: []structB{
			newStructB(*ID),
			newStructB(*ID),
		},
		Id:          ID,
		DisplayName: createUniqString(),
		Path:        &path,
	}
	err := AnonymizeNsx(sa)
	require.Equal(t, nil, err)
	saID := "structA.ID:10000"
	bID := "structB.ID:10003"
	require.Equal(t, saID, *sa.Id)
	require.Equal(t, saID, *sa.BAsPointer.OwnerVmId)
	require.Equal(t, saID, *sa.BAsStruct.OwnerVmId)
	require.Equal(t, bID, *sa.BAsSlices[0].Id)
	require.Equal(t, fmt.Sprintf("/infra/As/%s/Bs/%s", saID, bID), *sa.BAsSlices[0].Path)
	require.Equal(t, (*string)(nil), sa.BAsSlices[1].TargetId)
}
