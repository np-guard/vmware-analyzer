/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
	"slices"

	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

// ////////////////////////////////////////////////////
type Tier0 struct {
	resources.Tier0
}
type Tier1 struct {
	resources.Tier1
}

////////////////////////////////////////////////////

// //////////////////////////////////////////////////
const (
	tier0Query = "policy/api/v1/infra/tier-0s"
	tier1Query = "policy/api/v1/infra/tier-1s"
)

func collectorNewCodeGateway(server serverData, res *ResourcesContainerModel) (error, error) {

	err := collectResultList(server, tier0Query, &res.Tier0List)
	if err != nil {
		return nil, err
	}
	err = collectResultList(server, tier1Query, &res.Tier1List)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// //////////////////////////////////////////////////
func testNewCodeGateway(got *ResourcesContainerModel) {
	for _, segment := range got.SegmentList {
		if segment.ConnectivityPath == nil{
			fmt.Printf("[segment, type]: [%s, %s] has no ConnectivityPath\n", *segment.DisplayName, *segment.Type)
			continue
		}
		if t1 := got.GetTier1(*segment.ConnectivityPath); t1 != nil{
			t0 := got.GetTier0(*t1.Tier0Path)
			fmt.Printf("[segment, type, t1, t0]: [%s, %s, %s, %s]\n", *segment.DisplayName, *segment.Type, *t1.DisplayName, *t0.DisplayName)
		}else if t0 := got.GetTier0(*segment.ConnectivityPath); t0 != nil{
			fmt.Printf("[segment, type, t0]: [%s, %s, %s]\n", *segment.DisplayName, *segment.Type, *t0.DisplayName)
		}else{
			fmt.Printf("fail to find tier of [segment, type]: [%s, %s] with connectivity %s\n", *segment.DisplayName, *segment.Type, *segment.ConnectivityPath)
		}
		
	}
}

////////////////////////////////////////////////////

func (resources *ResourcesContainerModel) GetTier0(query string) *Tier0 {
	i := slices.IndexFunc(resources.Tier0List, func(t Tier0) bool { return query == *t.Path })
	if i >= 0 {
		return &resources.Tier0List[i]
	}
	return nil
}
func (resources *ResourcesContainerModel) GetTier1(query string) *Tier1 {
	i := slices.IndexFunc(resources.Tier1List, func(t Tier1) bool { return query == *t.Path })
	if i >= 0 {
		return &resources.Tier1List[i]
	}
	return nil
}
