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
	groupQuery               = "policy/api/v1/infra/domains/%s/groups/%s"
	groupMembersQuery        = "policy/api/v1/infra/domains/%s/groups/%s/members/virtual-machines"
	securityPolicyQuery      = "policy/api/v1/infra/domains/%s/security-policies"
	securityPolicyRulesQuery = "policy/api/v1/infra/domains/%s/security-policies/%s"
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
	collectorNewCode(server, res)
	for di := range res.DomainList {
		domainID := *res.DomainList[di].Id
		domainResouces := &res.DomainList[di].Resources
		err = collectResultList(server, fmt.Sprintf(groupsQuery, domainID), &domainResouces.GroupList)
		if err != nil {
			return nil, err
		}
		for i := range domainResouces.GroupList {
			err = collectExpressionList(server, fmt.Sprintf(groupQuery, domainID, *domainResouces.GroupList[i].Id), &domainResouces.GroupList[i].Expression)
			if err != nil {
				return nil, err
			}
			err = collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResouces.GroupList[i].Id), &domainResouces.GroupList[i].Members)
			if err != nil {
				return nil, err
			}
		}
		err = collectResultList(server, fmt.Sprintf(securityPolicyQuery, domainID), &domainResouces.SecurityPolicyList)
		if err != nil {
			return nil, err
		}
		for i := range domainResouces.SecurityPolicyList {
			err = collectRulesList(server, fmt.Sprintf(securityPolicyRulesQuery, domainID, *domainResouces.SecurityPolicyList[i].Id), &domainResouces.SecurityPolicyList[i].Rules)
			if err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}
