/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
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
	tier0Query     = "/policy/api/v1/infra/tier-0s"
	tier1Query     = "/policy/api/v1/infra/tier-1s"
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
	// for si := range res.SegmentList {
	// 	segmentID := *res.SegmentList[si].Id
	// 	err = collectResultList(server, fmt.Sprintf(segmentPortsQuery, segmentID), &res.SegmentList[si].SegmentPorts)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	return nil, nil
}

// //////////////////////////////////////////////////
// func testNewCode(got *ResourcesContainerModel) {
// 	for _, segment := range got.SegmentList {
// 		for _, port := range segment.SegmentPorts {
// 			att := *port.Attachment.Id
// 			vif := got.GetVirtualNetworkInterfaceByPort(att)
// 			vm := got.GetVirtualMachine(*vif.OwnerVmId)
// 			fmt.Printf("[segment, vm]: [%s, %s]\n", *segment.DisplayName, *vm.DisplayName)
// 		}
// 	}
// }

////////////////////////////////////////////////////
