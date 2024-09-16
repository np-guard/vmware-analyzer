/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
)

const (
	domainsQuery             = "policy/api/v1/infra/domains"
	servicesQuery            = "policy/api/v1/infra/services"
	segmentsQuery            = "policy/api/v1/infra/segments"
	virtualMachineQuery      = "api/v1/fabric/virtual-machines"
	groupsQuery              = "policy/api/v1/infra/domains/%s/groups"
	securityPolicyQuery      = "policy/api/v1/infra/domains/%s/security-policies"
	securityPolicyRulesQuery = "policy/api/v1/infra/domains/%s/security-policies/%s"
	groupMembersQuery        = "policy/api/v1/infra/domains/%s/groups/%s/members/virtual-machines"
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
	err = collectResultList(server, servicesQuery, &res.ServiceList)
	if err != nil {
		return nil, err
	}
	err = collectResultList(server, domainsQuery, &res.DomainList)
	if err != nil {
		return nil, err
	}
	err = collectResultList(server, segmentsQuery, &res.SegmentList)
	if err != nil {
		return nil, err
	}

	for di := range res.DomainList {
		domain := &res.DomainList[di]
		domainID := *domain.Id
		err = collectResultList(server, fmt.Sprintf(groupsQuery, domainID), &domain.GroupList)
		if err != nil {
			return nil, err
		}
		for i := range domain.GroupList {
			err = collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domain.GroupList[i].Id), &domain.GroupList[i].Members)
			if err != nil {
				return nil, err
			}
		}
		err = collectResultList(server, fmt.Sprintf(securityPolicyQuery, domainID), &domain.SecurityPolicyList)
		if err != nil {
			return nil, err
		}
		for i := range domain.SecurityPolicyList {
			err = collectRulesList(server, fmt.Sprintf(securityPolicyRulesQuery, domainID, *domain.SecurityPolicyList[i].Id), &domain.SecurityPolicyList[i].Rules)
			if err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}
