/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:stylecheck // names should be as in rest output
package vsphrcoll

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
)

const (
	virtualMachineQuery = "api/vcenter/vm"
)

type portResource struct {
	Label                        string
	Type                         string
	Upt_compatibility_enabled    bool
	Upt_v2_compatibility_enabled bool
	Mac_type                     string
	Mac_address                  string
	Pci_slot_number              int
	Wake_on_lan_enabled          bool
	Backing                      struct {
		Type                    string
		Network                 string
		Network_name            string
		Host_device             string
		Distributed_switch_uuid string
		Distributed_port        string
		Connection_cookie       int
		Opaque_network_type     string
		Opaque_network_id       string
	}
	State               string
	Start_connected     bool
	Allow_guest_control bool
}

type vmResource struct {
	Vm              string
	Name            string
	Power_state     string
	Cpu_count       int
	Memory_size_MiB int
	VmInfo          vmInfo
}

type vmInfo struct {
	Guest_OS string
	Name     string
	Identity struct {
		Name          string
		Bios_uuid     string
		Instance_uuid string
	}
	Nics           map[int]*portResource
	Parallel_ports map[int]struct {
		Label   string
		Backing struct {
			Type        string
			File        string
			Host_device string
			Auto_detect bool
		}
		State               string
		Start_connected     bool
		Allow_guest_control bool
	}
	Serial_ports map[int]struct {
		Label         string
		Yield_on_poll bool
		Backing       struct {
			Type             string
			File             string
			Host_device      string
			Auto_detect      bool
			Pipe             string
			No_rx_loss       bool
			Network_location string
			Proxy            string
		}
		State               string
		Start_connected     bool
		Allow_guest_control bool
	}
}
type ResourcesContainerModel struct {
	Vms   []vmResource
	Ports map[string]*portResource
}

func NewResourcesContainerModel() *ResourcesContainerModel {
	return &ResourcesContainerModel{
		Ports: map[string]*portResource{},
	}
}

// ToJSONString converts a ResourcesContainerModel into a json-formatted-string
func (resources *ResourcesContainerModel) ToJSONString() (string, error) {
	return common.MarshalJSON(resources)
}

func CollectResources(nsxServer, userName, password string, insecureSkipVerify bool) (*ResourcesContainerModel, error) {
	server := &serverData{nsxServer, userName, password, "", insecureSkipVerify}
	res := NewResourcesContainerModel()
	err := collectResource(server, virtualMachineQuery, &res.Vms)
	if err != nil {
		return nil, err
	}
	for vi := range res.Vms {
		err = collectResource(server, virtualMachineQuery+"/"+res.Vms[vi].Vm, &res.Vms[vi].VmInfo)
		if err != nil {
			return nil, err
		}
		for _, p := range res.Vms[vi].VmInfo.Nics {
			res.Ports[p.Backing.Network] = p
		}
	}
	return res, nil
}
