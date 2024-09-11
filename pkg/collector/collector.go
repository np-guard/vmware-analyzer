/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
)

const (
	virtualMachineQuary = "api/v1/fabric/virtual-machines"
	securityPolicyQuary = "policy/api/v1/infra/domains/%s/security-policies"
	domainsQuary        = "policy/api/v1/infra/domains"
)

type serverData struct {
	NSXServer, user_name, password string
}

func CollectResources(NSXServer, user_name, password string) (*ResourcesContainerModel, error) {
	server := serverData{NSXServer, user_name, password}
	res := NewResourcesContainerModel()
	err := collectResourceList(server, virtualMachineQuary, &res.VirtualMachineList)
	if err != nil {
		return nil, err
	}
	domain, err := getDomain(server)
	if err != nil {
		return nil, err
	}
	err = collectResourceList(server, fmt.Sprintf(securityPolicyQuary, domain), &res.SecurityPolicyList)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func getDomain(server serverData) (string, error) {
	type domain struct {
		Id string
	}
	domains := []*domain{}
	err := collectResourceList(server, domainsQuary, &domains)
	if err != nil {
		return "", err
	}
	if len(domains) == 0 {
		return "", fmt.Errorf("failed to find domain")
	}
	if len(domains) > 1 {
		return "", fmt.Errorf("multplied domains are not supported")
	}
	return domains[0].Id, nil
}
