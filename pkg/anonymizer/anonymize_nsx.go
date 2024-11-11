/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"strings"
)

func AnonymizeNsx(st structInstance) error {
	return anonymize(st, nxsAnonInstruction())
}

func ipAddressFilter(ip string) bool {
	tokens := strings.Split(ip, ".")
	return len(tokens) == 4 && tokens[0] != "192"
}

func nxsAnonInstruction() *anonInstruction {
	//revive:disable // these are the fields names
	return &anonInstruction{
		pkgsToSkip: []string{
			"collector",
		},
		structsToSkip: []string{
			"ServiceEntry",
			"Expression",
		},
		refStructs: map[string]string{
			"RealizedVirtualMachine": "VirtualMachine",
		},
		structsToNotAnonFields: []string{
			"Service",
			"IPProtocolServiceEntry",
			"IGMPTypeServiceEntry",
			"ICMPTypeServiceEntry",
			"ALGTypeServiceEntry",
			"L4PortSetServiceEntry",
			"EtherTypeServiceEntry",
			"NestedServiceServiceEntry",
		},
		idFields: []string{
			"ExternalId",
			"UniqueId",
			"Id",
		},
		idsToKeep: []idToKeep{
			{"Service", "Id"},
			{"IPProtocolServiceEntry", "Id"},
			{"IGMPTypeServiceEntry", "Id"},
			{"ICMPTypeServiceEntry", "Id"},
			{"ALGTypeServiceEntry", "Id"},
			{"L4PortSetServiceEntry", "Id"},
			{"EtherTypeServiceEntry", "Id"},
			{"NestedServiceServiceEntry", "Id"},
		},

		idRefFields: []string{
			"RealizationId",
			"OwnerVmId",
			"SectionId",
			"HostId",
			"OwnerId",
			"TargetId",
			"RelativePath",
			"RealizationSpecificIdentifier",
			"LportAttachmentId",
		},
		fields: []string{
			"ComputerName",
			"DisplayName",
			"DeviceName",
			"Description",
			"MacAddress",
		},

		fieldsByCondition: []conditionField{
			{"DefaultGateway", ipAddressFilter},
			{"RdAdminField", ipAddressFilter},
		},

		slicesByCondition: []conditionField{
			{"IpAddresses", ipAddressFilter},
			{"DnsServers", ipAddressFilter},
			{"OptimizedIps", ipAddressFilter},
			{"DhcpRanges", ipAddressFilter},
			{"TransitSubnets", ipAddressFilter},
			{"InternalTransitSubnets", ipAddressFilter},
			{"VrfTransitSubnets", ipAddressFilter},
		},
		fieldsByRef: []byRefField{
			{"TargetDisplayName", "TargetId", "DisplayName"},
		},
		fieldsToClear: []string{
			"ComputeIds",
		},
		idToCreateIfNotFound: []string{
			"LportAttachmentId",
			"HostId",
			"OwnerId",
		},
		pathFields: []string{
			"Path",
			"ParentPath",
			"ConnectivityPath",
			"Tier0Path",
		},
		pathToCleanFields: []string{
			"BridgeProfilePath",
			"DhcpConfigPath",
			"EgressQosProfilePath",
			"EvpnTenantConfigPath",
			"IngressQosProfilePath",
			"L2VpnPath",
			"NdraProfilePath",
			"NestedServicePath",
			"PrimarySitePath",
			"RemotePath",
			"SchedulerPath",
			"TargetResourcePath",
			"TransportZonePath",
			"VlanTransportZonePath",
		},
		rootPaths: []string{
			"/infra",
			"/infra/realized-state",
		},
	}
}
