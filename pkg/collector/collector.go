/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
	"slices"
	"strings"

	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

const (
	domainsQuery                = "policy/api/v1/infra/domains"
	servicesQuery               = "policy/api/v1/infra/services"
	segmentsQuery               = "policy/api/v1/infra/segments"
	segmentPortsQuery           = "policy/api/v1/infra/segments/%s/ports"
	tier0Query                  = "policy/api/v1/infra/tier-0s"
	tier1Query                  = "policy/api/v1/infra/tier-1s"
	tierNatQuery                = "%s/%s/nat"
	tierNatRuleQuery            = "%s/%s/nat/%s/nat-rules"
	virtualMachineQuery         = "api/v1/fabric/virtual-machines"
	virtualInterfaceQuery       = "api/v1/fabric/vifs"
	groupsQuery                 = "policy/api/v1/infra/domains/%s/groups"
	groupQuery                  = "policy/api/v1/infra/domains/%s/groups/%s"
	groupMemberTypesQuery       = "policy/api/v1/infra/domains/%s/groups/%s/member-types"
	groupMembersQuery           = "policy/api/v1/infra/domains/%s/groups/%s/members/%s"
	securityPoliciesQuery       = "policy/api/v1/infra/domains/%s/security-policies"
	securityPolicyRulesQuery    = "policy/api/v1/infra/domains/%s/security-policies/%s"
	securityPolicyRuleQuery     = "policy/api/v1/infra/domains/%s/security-policies/%s/rules/%s"
	gatewayPoliciesQuery        = "policy/api/v1/infra/domains/%s/gateway-policies"
	gatewayPolicyRulesQuery     = "policy/api/v1/infra/domains/%s/gateway-policies/%s"
	gatewayPolicyRuleQuery      = "policy/api/v1/infra/domains/%s/gateway-policies/%s/rules/%s"
	redirectionPoliciesQuery    = "policy/api/v1/infra/domains/%s/redirection-policies"
	redirectionPolicyRulesQuery = "policy/api/v1/infra/domains/%s/redirection-policies/%s"
	redirectionPolicyRuleQuery  = "policy/api/v1/infra/domains/%s/redirection-policies/%s/rules/%s"
	firewallRuleQuery           = "api/v1/firewall/rules/%d"

	defaultForwardingUpTimer = 5
)

var supportedMembersTypes = []string{
	"Segment", "SegmentPort",
	"VirtualMachine", "VirtualNetworkInterface",
	"IPAddress", "TransportNode", "Group"}

type ServerData struct {
	host, user, password      string
	disableInsecureSkipVerify bool
}

func NewServerData(host, user, password string, disableInsecureSkipVerify bool) ServerData {
	return ServerData{host, user, password, disableInsecureSkipVerify}
}

func ValidateNSXConnection(host, user, password string, disableInsecureSkipVerify bool) (string, error) {
	res := NewResourcesContainerModel()
	// vms:
	err := collectResultList(NewServerData(host, user, password, disableInsecureSkipVerify), virtualMachineQuery, &res.VirtualMachineList)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("found %d vms", len(res.VirtualMachineList)), nil
}

//nolint:funlen,gocyclo // just a long function
func CollectResources(server ServerData) (*ResourcesContainerModel, error) {
	res := NewResourcesContainerModel()
	// vms:
	err := collectResultList(server, virtualMachineQuery, &res.VirtualMachineList)
	if err != nil {
		return nil, err
	}
	// vnis:
	err = collectResultList(server, virtualInterfaceQuery, &res.VirtualNetworkInterfaceList)
	if err != nil {
		return nil, err
	}
	// services:
	err = collectResultList(server, servicesQuery, &res.ServiceList)
	if err != nil {
		return nil, err
	}
	//segments:
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
	// tier0:
	err = collectResultList(server, tier0Query, &res.Tier0List)
	if err != nil {
		return nil, err
	}
	for ti := range res.Tier0List {
		tID := *res.Tier0List[ti].Id
		err = collcetPolicyNats(server, tier0Query, tID, &res.Tier0List[ti].PolicyNats)
		if err != nil {
			return nil, err
		}
	}
	// tier1:
	err = collectResultList(server, tier1Query, &res.Tier1List)
	if err != nil {
		return nil, err
	}
	for ti := range res.Tier1List {
		tID := *res.Tier1List[ti].Id
		err = collcetPolicyNats(server, tier1Query, tID, &res.Tier1List[ti].PolicyNats)
		if err != nil {
			return nil, err
		}
	}
	//domains:
	err = collectResultList(server, domainsQuery, &res.DomainList)
	if err != nil {
		return nil, err
	}
	for di := range res.DomainList {
		domainID := *res.DomainList[di].Id
		domainResources := &res.DomainList[di].Resources
		// groups:
		err = collectResultList(server, fmt.Sprintf(groupsQuery, domainID), &domainResources.GroupList)
		if err != nil {
			return nil, err
		}
		for i := range domainResources.GroupList {
			group := &domainResources.GroupList[i]
			err = collectResource(server, fmt.Sprintf(groupQuery, domainID, *domainResources.GroupList[i].Id), group)
			if err != nil {
				return nil, err
			}
			var memberTypes []string
			if err := collectResultList(server, fmt.Sprintf(groupMemberTypesQuery, domainID, *domainResources.GroupList[i].Id),
				&memberTypes); err != nil {
				return nil, err
			}
			nonSuppoertedTypes := slices.DeleteFunc(memberTypes, func(t string) bool { return slices.Contains(supportedMembersTypes, t) })
			if len(nonSuppoertedTypes) > 0 {
				logging.Warnf("collecting [%s] for group %s are not supported", strings.Join(nonSuppoertedTypes, ","), *group.DisplayName)
			}
			if err := collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id,
				"virtual-machines"), &group.VMMembers); err != nil {
				return nil, err
			}
			if err := collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id,
				"vifs"), &group.VIFMembers); err != nil {
				return nil, err
			}
			if err := collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id,
				"ip-addresses"), &group.AddressMembers); err != nil {
				return nil, err
			}
			if err := collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id,
				"segments"), &group.Segments); err != nil {
				return nil, err
			}
			if err := collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id,
				"segment-ports"), &group.SegmentPorts); err != nil {
				return nil, err
			}
			if err := collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id,
				"ip-groups"), &group.IPGroups); err != nil {
				return nil, err
			}
			if err := collectResultList(server, fmt.Sprintf(groupMembersQuery, domainID, *domainResources.GroupList[i].Id,
				"transport-nodes"), &group.TransportNodes); err != nil {
				return nil, err
			}
		}
		// security policies:
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
				domainResources.SecurityPolicyList[si].Rules[ri].FirewallRule = &FirewallRule{}
				err = collectResource(server,
					fmt.Sprintf(firewallRuleQuery,
						*domainResources.SecurityPolicyList[si].Rules[ri].RuleId),
					domainResources.SecurityPolicyList[si].Rules[ri].FirewallRule)
				if err != nil {
					return nil, err
				}
			}
		}
		// gateway policies:
		err = collectResultList(server,
			fmt.Sprintf(gatewayPoliciesQuery, domainID),
			&domainResources.GatewayPolicyList)
		if err != nil {
			return nil, err
		}
		for gi := range domainResources.GatewayPolicyList {
			err = collectResource(server,
				fmt.Sprintf(gatewayPolicyRulesQuery, domainID, *domainResources.GatewayPolicyList[gi].Id),
				&domainResources.GatewayPolicyList[gi])
			if err != nil {
				return nil, err
			}
			for ri := range domainResources.GatewayPolicyList[gi].Rules {
				err = collectResource(server,
					fmt.Sprintf(gatewayPolicyRuleQuery, domainID,
						*domainResources.GatewayPolicyList[gi].Id, *domainResources.GatewayPolicyList[gi].Rules[ri].Id),
					&domainResources.GatewayPolicyList[gi].Rules[ri])
				if err != nil {
					return nil, err
				}
			}
		}
		// redirection policies:
		err = collectResultList(server,
			fmt.Sprintf(redirectionPoliciesQuery, domainID),
			&domainResources.RedirectionPolicyList)
		if err != nil {
			return nil, err
		}
		for gi := range domainResources.RedirectionPolicyList {
			err = collectResource(server,
				fmt.Sprintf(redirectionPolicyRulesQuery, domainID, *domainResources.RedirectionPolicyList[gi].Id),
				&domainResources.RedirectionPolicyList[gi])
			if err != nil {
				return nil, err
			}
			for ri := range domainResources.RedirectionPolicyList[gi].RedirectionRules {
				err = collectResource(server,
					fmt.Sprintf(redirectionPolicyRuleQuery, domainID,
						*domainResources.RedirectionPolicyList[gi].Id, *domainResources.RedirectionPolicyList[gi].RedirectionRules[ri].Id),
					&domainResources.RedirectionPolicyList[gi].RedirectionRules[ri])
				if err != nil {
					return nil, err
				}
			}
		}
		err = collectResultList(server,
			fmt.Sprintf(gatewayPoliciesQuery, domainID),
			&domainResources.GatewayPolicyList)
		if err != nil {
			return nil, err
		}
		for gi := range domainResources.GatewayPolicyList {
			err = collectResource(server,
				fmt.Sprintf(gatewayPolicyRulesQuery, domainID, *domainResources.GatewayPolicyList[gi].Id),
				&domainResources.GatewayPolicyList[gi])
			if err != nil {
				return nil, err
			}
			for ri := range domainResources.GatewayPolicyList[gi].Rules {
				err = collectResource(server,
					fmt.Sprintf(gatewayPolicyRuleQuery, domainID,
						*domainResources.GatewayPolicyList[gi].Id, *domainResources.GatewayPolicyList[gi].Rules[ri].Id),
					&domainResources.GatewayPolicyList[gi].Rules[ri])
				if err != nil {
					return nil, err
				}
			}
		}
	}
	FixResourcesForJSON(res)
	return res, nil
}

func collcetPolicyNats(server ServerData, tierQuery, tID string, policyNats *[]PolicyNat) error {
	err := collectResultList(server, fmt.Sprintf(tierNatQuery, tierQuery, tID), policyNats)
	if err != nil {
		return err
	}
	for ni := range *policyNats {
		nID := *(*policyNats)[ni].Id
		err = collectResultList(server, fmt.Sprintf(tierNatRuleQuery, tierQuery, tID, nID), &(*policyNats)[ni].Rules)
		if err != nil {
			return err
		}
	}
	return nil
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
	tagOrig nsx.Tag
}

func (tag *Tag) Name() string {
	return tag.tagOrig.Tag
}
