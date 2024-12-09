/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"

	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	domainsQuery               = "policy/api/v1/infra/domains"
	servicesQuery              = "policy/api/v1/infra/services"
	segmentsQuery              = "policy/api/v1/infra/segments"
	segmentPortsQuery          = "policy/api/v1/infra/segments/%s/ports"
	tier0Query                 = "policy/api/v1/infra/tier-0s"
	tier1Query                 = "policy/api/v1/infra/tier-1s"
	virtualMachineQuery        = "api/v1/fabric/virtual-machines"
	virtualInterfaceQuery      = "api/v1/fabric/vifs"
	groupsQuery                = "policy/api/v1/infra/domains/%s/groups"
	groupQuery                 = "policy/api/v1/infra/domains/%s/groups/%s"
	groupMembersVMQuery        = "policy/api/v1/infra/domains/%s/groups/%s/members/virtual-machines"
	groupMembersVIFQuery       = "policy/api/v1/infra/domains/%s/groups/%s/members/vifs"
	groupMembersIPAddressQuery = "policy/api/v1/infra/domains/%s/groups/%s/members/ip-addresses"
	securityPoliciesQuery      = "policy/api/v1/infra/domains/%s/security-policies"
	securityPolicyRulesQuery   = "policy/api/v1/infra/domains/%s/security-policies/%s"
	securityPolicyRuleQuery    = "policy/api/v1/infra/domains/%s/security-policies/%s/rules/%s"
	firewallRuleQuery          = "api/v1/firewall/rules/%d"

	defaultForwardingUpTimer = 5
)

type ServerData struct {
	host, user, password string
}

func NewServerData(host, user, password string) ServerData {
	return ServerData{host, user, password}
}

//nolint:funlen,gocyclo // just a long function
func CollectResources(server ServerData) (*ResourcesContainerModel, error) {
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
				fmt.Sprintf(groupMembersVMQuery, domainID, *domainResources.GroupList[i].Id),
				&domainResources.GroupList[i].VMMembers)
			if err != nil {
				return nil, err
			}
			err = collectResultList(server,
				fmt.Sprintf(groupMembersVIFQuery, domainID, *domainResources.GroupList[i].Id),
				&domainResources.GroupList[i].VIFMembers)
			if err != nil {
				return nil, err
			}
			err = collectResultList(server,
				fmt.Sprintf(groupMembersIPAddressQuery, domainID, *domainResources.GroupList[i].Id),
				&domainResources.GroupList[i].AddressMembers)
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

// Tag a tag used by VMs for labeling in NSX
type Tag struct {
	tagOrig resources.Tag
}

func (tag *Tag) Name() string {
	return tag.tagOrig.Tag
}
