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
	segmentPortsQuery        = "policy/api/v1/infra/segments/%s/ports"
	tier0Query               = "policy/api/v1/infra/tier-0s"
	tier1Query               = "policy/api/v1/infra/tier-1s"
	virtualMachineQuery      = "api/v1/fabric/virtual-machines"
	virtualInterfaceQuery    = "api/v1/fabric/vifs"
	groupsQuery              = "policy/api/v1/infra/domains/%s/groups"
	groupQuery               = "policy/api/v1/infra/domains/%s/groups/%s"
	groupMembersQuery        = "policy/api/v1/infra/domains/%s/groups/%s/members/virtual-machines"
	securityPoliciesQuery    = "policy/api/v1/infra/domains/%s/security-policies"
	securityPolicyRulesQuery = "policy/api/v1/infra/domains/%s/security-policies/%s"
	securityPolicyRuleQuery  = "policy/api/v1/infra/domains/%s/security-policies/%s/rules/%s"
	firewallRuleQuery        = "api/v1/firewall/rules/%d"

	defaultForwardingUpTimer = 5
)

type serverData struct {
	nsxServer, userName, password string
}

//nolint:funlen,gocyclo // just a long function
func CollectResources(nsxServer, userName, password string) (*ResourcesContainerModel, error) {
	server := serverData{nsxServer, userName, password}
	res := NewResourcesContainerModel()
	err := collectResultList(server, virtualMachineQuery, &res.VirtualMachineList)
	if err != nil {
		return nil, err
	}
	err = collectResultList(server, virtualInterfaceQuery, &res.VirtualNetworkInterfaceList)
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
	for si := range res.SegmentList {
		segmentID := *res.SegmentList[si].Id
		err = collectResultList(server, fmt.Sprintf(segmentPortsQuery, segmentID), &res.SegmentList[si].SegmentPorts)
		if err != nil {
			return nil, err
		}
	}
	err = collectResultList(server, tier0Query, &res.Tier0List)
	if err != nil {
		return nil, err
	}
	err = collectResultList(server, tier1Query, &res.Tier1List)
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
			err = collectResultList(server,
				fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id),
				&domainResources.GroupList[i].Members)
			if err != nil {
				return nil, err
			}
		}
		err = collectResultList(server,
			fmt.Sprintf(securityPoliciesQuery, domainID),
			&domainResources.SecurityPolicyList)
		if err != nil {
			return nil, err
		}
		for si := range domainResources.SecurityPolicyList {
			err = collectResource(server,
				fmt.Sprintf(securityPolicyRulesQuery, domainID, *domainResources.SecurityPolicyList[si].Id),
				&domainResources.SecurityPolicyList[si])
			if err != nil {
				return nil, err
			}
			if domainResources.SecurityPolicyList[si].DefaultRuleId != nil {
				domainResources.SecurityPolicyList[si].DefaultRule = &FirewallRule{}
				err = collectResource(server,
					fmt.Sprintf(firewallRuleQuery, *domainResources.SecurityPolicyList[si].DefaultRuleId),
					domainResources.SecurityPolicyList[si].DefaultRule)
				if err != nil {
					return nil, err
				}
			}
			for ri := range domainResources.SecurityPolicyList[si].Rules {
				err = collectResource(server,
					fmt.Sprintf(securityPolicyRuleQuery, domainID,
						*domainResources.SecurityPolicyList[si].Id, *domainResources.SecurityPolicyList[si].Rules[ri].Id),
					&domainResources.SecurityPolicyList[si].Rules[ri])
				if err != nil {
					return nil, err
				}
				err = collectResource(server,
					fmt.Sprintf(firewallRuleQuery,
						*domainResources.SecurityPolicyList[si].Rules[ri].RuleId),
					&domainResources.SecurityPolicyList[si].Rules[ri].FirewallRule)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	FixResourcesForJSON(res)
	return res, nil
}

func FixResourcesForJSON(res *ResourcesContainerModel) {
	for i := range res.Tier0List {
		if res.Tier0List[i].AdvancedConfig != nil {
			if res.Tier0List[i].AdvancedConfig.ForwardingUpTimer == 0 {
				res.Tier0List[i].AdvancedConfig.ForwardingUpTimer = defaultForwardingUpTimer
			}
		}
	}
}
