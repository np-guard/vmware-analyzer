/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/logging"
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
	groupMembersTypesQuery   = "policy/api/v1/infra/domains/%s/groups/%s/member-types"
	groupMembersQuery        = "policy/api/v1/infra/domains/%s/groups/%s/members/%s"
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
			if err = collectResource(server, fmt.Sprintf(groupQuery, domainID, *domainResources.GroupList[i].Id), &domainResources.GroupList[i]); err != nil {
				return nil, err
			}
			var memberTypes []string
			if err = collectResultList(server,
				fmt.Sprintf(groupMembersTypesQuery, domainID, *domainResources.GroupList[i].Id),
				&memberTypes); err != nil {
				return nil, err
			}
			// types options:
			// VirtualMachine, VirtualNetworkInterface, SegmentPort, Segment, CloudNativeServiceInstance, IPAddress, MACAddress, IPSet,
			// IdentityGroup, PhysicalServer, Pod, Service, Namespace, Cluster, TransportNode, Group,
			// DVPG, DVPort, KubernetesCluster, KubernetesNamespace, AntreaEgress, AntreaIPPool,
			// KubernetesIngress, KubernetesGateway, KubernetesService, KubernetesNode, VpcSubnet, VpcSubnetPort
			for _, mType := range memberTypes {
				membersQuery := func(mType string) string {
					return fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id, mType)
				}
				switch mType {
				case "VirtualMachine":
					err = collectResultList(server, membersQuery("virtual-machines"), &domainResources.GroupList[i].VMs)
				case "VirtualNetworkInterface":
					err = collectResultList(server, membersQuery("vifs"), &domainResources.GroupList[i].VIFs)
				case "Segment":
					err = collectResultList(server, membersQuery("segments"), &domainResources.GroupList[i].Segments)
				case "SegmentPort":
					err = collectResultList(server, membersQuery("segment-ports"), &domainResources.GroupList[i].SegmentPorts)
				case "IPAddress":
					err = collectResultList(server, membersQuery("ip-addresses"), &domainResources.GroupList[i].IPAddresses)
				case "TransportNode":
					err = collectResultList(server, membersQuery("transport-nodes"), &domainResources.GroupList[i].TransportNodes)
				default:
					logging.Warnf("did not collect group members of type %s from group %s", mType, *domainResources.GroupList[i].DisplayName)
				}
				if err != nil {
					return nil, err
				}
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
