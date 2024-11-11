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
	Id           *string
	DisplayName  *string
	Path         *string
}
type structB struct {
	aSlice      []int
	Id          *string
	OwnerVmId   *string
	TargetId    *string
	DisplayName *string
	Path        *string
}

var uniqStringCounter = 0

func createUniqString() *string {
	uniqStringCounter++
	a := fmt.Sprintf("str%d", uniqStringCounter)
	return &a
}
func newStructB(OwnerVmId string) structB {
	Id := createUniqString()
	path := fmt.Sprintf("/infra/As/%s/Bs/%s", OwnerVmId, *Id)

	return structB{aSlice: []int{6, 7},
		Id:          Id,
		DisplayName: createUniqString(),
		OwnerVmId:   &OwnerVmId,
		Path:        &path}
}
func newStructBPointer(OwnerVmId string) *structB {
	b := newStructB(OwnerVmId)
	return &b
}

func Test_anonymize(t *testing.T) {
	Id := createUniqString()
	path := fmt.Sprintf("/infra/As/%s", *Id)
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
	err := AnonymizeNsx(sa)
	require.Equal(t, nil, err)
	saId := "structA.Id:10000"
	bId := "structB.Id:10003"
	require.Equal(t, saId, *sa.Id)
	require.Equal(t, saId, *sa.BAsPointer.OwnerVmId)
	require.Equal(t, saId, *sa.BAsStruct.OwnerVmId)
	require.Equal(t, bId, *sa.BAsSlices[0].Id)
	require.Equal(t, fmt.Sprintf("/infra/As/%s/Bs/%s", saId, bId), *sa.BAsSlices[0].Path)
	require.Equal(t, (*string)(nil), sa.BAsSlices[1].TargetId)
}
