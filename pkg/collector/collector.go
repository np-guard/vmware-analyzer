/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
)

const (
	domainsQuery            = "policy/api/v1/infra/domains"
	servicesQuery           = "policy/api/v1/infra/services"
	serviceEntriesQuery     = "policy/api/v1/infra/services/%s/service-entries"
	segmentsQuery           = "policy/api/v1/infra/segments"
	virtualMachineQuery     = "api/v1/fabric/virtual-machines"
	groupsQuery             = "policy/api/v1/infra/domains/%s/groups"
	groupQuery              = "policy/api/v1/infra/domains/%s/groups/%s"
	groupMembersQuery       = "policy/api/v1/infra/domains/%s/groups/%s/members/virtual-machines"
	securityPoliciesQuery   = "policy/api/v1/infra/domains/%s/security-policies"
	securityPolicyQuery     = "policy/api/v1/infra/domains/%s/security-policies/%s"
	securityPolicyRuleQuery = "policy/api/v1/infra/domains/%s/security-policies/%s/rules/%s"
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
	for si := range res.ServiceList {
		err = collectResultList(server, fmt.Sprintf(serviceEntriesQuery, *res.ServiceList[si].Id), &res.ServiceList[si].ServiceEntries)
		if err != nil {
			return nil, err
		}
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
		domainID := *res.DomainList[di].Id
		domainResources := &res.DomainList[di].Resources
		err = collectResultList(server, fmt.Sprintf(groupsQuery, domainID), &domainResources.GroupList)
		if err != nil {
			return nil, err
		}
		for i := range domainResources.GroupList {
			err = collectResource(server, fmt.Sprintf(groupQuery, domainID, *domainResources.GroupList[i].Id), &domainResources.GroupList[i])
			if err != nil {
				return nil, err
			}
			err = collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id), &domainResources.GroupList[i].Members)
			if err != nil {
				return nil, err
			}
		}
		err = collectResultList(server, fmt.Sprintf(securityPoliciesQuery, domainID), &domainResources.SecurityPolicyList)
		if err != nil {
			return nil, err
		}
		for si := range domainResources.SecurityPolicyList {
			err = collectResource(server, fmt.Sprintf(securityPolicyQuery, domainID, *domainResources.SecurityPolicyList[si].Id), &domainResources.SecurityPolicyList[si])
			if err != nil {
				return nil, err
			}
			for ri := range domainResources.SecurityPolicyList[si].Rules {
				err = collectResource(server, fmt.Sprintf(securityPolicyRuleQuery, domainID, *domainResources.SecurityPolicyList[si].Id, *domainResources.SecurityPolicyList[si].Rules[ri].Id), &domainResources.SecurityPolicyList[si].Rules[ri])
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return res, nil
}
