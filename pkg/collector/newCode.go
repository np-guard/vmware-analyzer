/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"fmt"
	"slices"

	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

// ////////////////////////////////////////////////////
type VirtualNetworkInterface struct {
	resources.VirtualNetworkInterface
}
type Segment struct {
	resources.Segment
	SegmentPorts []SegmentPort `json:"segment_ports"`
}

func (d *Segment) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var res Segment
	if err := json.Unmarshal(b, &res.Segment); err != nil {
		return err
	}
	if m, ok := raw["segment_ports"]; ok {
		if err := json.Unmarshal(m, &res.SegmentPorts); err != nil {
			return err
		}
	}
	*d = res
	return nil
}

type SegmentPort struct {
	resources.SegmentPort
}

////////////////////////////////////////////////////

func (resources *ResourcesContainerModel) GetVirtualNetworkInterfaceByPort(portID string) *VirtualNetworkInterface {
	i := slices.IndexFunc(resources.VirtualNetworkInterfaceList, func(vni VirtualNetworkInterface) bool {
		return vni.LportAttachmentId != nil && portID == *vni.LportAttachmentId
	})
	return &resources.VirtualNetworkInterfaceList[i]
}

func (resources *ResourcesContainerModel) GetVirtualMachine(id string) *VirtualMachine {
	i := slices.IndexFunc(resources.VirtualMachineList, func(vm VirtualMachine) bool { return id == *vm.ExternalId })
	return &resources.VirtualMachineList[i]
}

// //////////////////////////////////////////////////
const (
	segmentPortsQuery     = "policy/api/v1/infra/segments/%s/ports"
	virtualInterfaceQuery = "api/v1/fabric/vifs"
)

func collectorNewCode(server serverData, res *ResourcesContainerModel) (error, error) {

	err := collectResultList(server, virtualInterfaceQuery, &res.VirtualNetworkInterfaceList)
	if err != nil {
		return nil, err
	}
	for si := range res.SegmentList {
		segmentID := *res.SegmentList[si].Id
		err = collectResultList(server, fmt.Sprintf(segmentPortsQuery, segmentID), &res.SegmentList[si].SegmentPorts)
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// //////////////////////////////////////////////////
func testNewCode(got *ResourcesContainerModel) {
	for _, segment := range got.SegmentList {
		for _, port := range segment.SegmentPorts {
			att := *port.Attachment.Id
			vif := got.GetVirtualNetworkInterfaceByPort(att)
			vm := got.GetVirtualMachine(*vif.OwnerVmId)
			fmt.Printf("[segment, vm]: [%s, %s]\n", *segment.DisplayName, *vm.DisplayName)
		}
	}
}

////////////////////////////////////////////////////
