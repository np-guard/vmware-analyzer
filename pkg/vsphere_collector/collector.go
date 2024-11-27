/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vsphere_collector

import "encoding/json"

const (
	virtualMachineQuery = "api/vcenter/vm"
)

type ResourcesContainerModel struct {
	vms []json.RawMessage
}

//nolint:funlen,gocyclo // just a long function
func CollectResources(nsxServer, userName, password string) (*ResourcesContainerModel, error) {
	server := serverData{nsxServer, userName, password, ""}
	res := &ResourcesContainerModel{}
	err := collectResources(server, virtualMachineQuery, &res.vms)
	if err != nil {
		return nil, err
	}
	return res, nil
}
