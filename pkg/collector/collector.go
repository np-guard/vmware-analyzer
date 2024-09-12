/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
)

const (
	virtualMachineQuery      = "api/v1/fabric/virtual-machines"
	securityPolicyQuery      = "policy/api/v1/infra/domains/%s/security-policies"
	securityPolicyRulesQuery = "policy/api/v1/infra/domains/%s/security-policies/%s"
	domainsQuery             = "policy/api/v1/infra/domains"
)

type serverData struct {
	nsxServer, userName, password string
}

func CollectResources(nsxServer, userName, password string) (*ResourcesContainerModel, error) {
	server := serverData{nsxServer, userName, password}
	res := NewResourcesContainerModel()
	err := collectResultList(server, virtualMachineQuery, &res.VirtualMachineList)
	if err != nil {
		return nil, err
	}
	domain, err := getDomain(server)
	if err != nil {
		return nil, err
	}
	err = collectResultList(server, fmt.Sprintf(securityPolicyQuery, domain), &res.SecurityPolicyList)
	if err != nil {
		return nil, err
	}
	for i := range res.SecurityPolicyList {
		err = collectRulesList(server, fmt.Sprintf(securityPolicyRulesQuery, domain, *res.SecurityPolicyList[i].Id), &res.SecurityPolicyList[i].Rules)
		if err != nil {
			return nil, err
		}

	}

	return res, nil
}

func getDomain(server serverData) (string, error) {
	type domain struct {
		ID string
	}
	domains := []*domain{}
	err := collectResultList(server, domainsQuery, &domains)
	if err != nil {
		return "", err
	}
	if len(domains) == 0 {
		return "", fmt.Errorf("failed to find domain")
	}
	if len(domains) > 1 {
		return "", fmt.Errorf("multiple domains are not supported")
	}
	return domains[0].ID, nil
}
