/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"strings"
)

func Anonymize(st interface{}) {
	anonymizer := newAnonymizer(nxsAnonInstruction())
	iterate(st, anonymizer, collectIDsToKeep, toAnonymizeFilter)
	iterate(st, anonymizer, anonymizeIDs, toAnonymizeFilter)
	iterate(st, anonymizer, anonymizeRefs, toAnonymizeFilter)
	iterate(st, anonymizer, collectPaths, toAnonymizeFilter)
	anonymizer.anonymizeAllPaths()
	iterate(st, anonymizer, anonymizePaths, toAnonymizeFilter)
	iterate(st, anonymizer, anonymizeFields, toAnonymizeFilter)
}

func nxsAnonInstruction() *anonInstruction {
	//revive:disable // these are the fields names
	ipAddressFilter := func(ip string) bool {
		tokens := strings.Split(ip, ".")
		return len(tokens) == 4 && tokens[0] != "192"
	}
	return &anonInstruction{
		theReferenceField: "ID",
		pkgsToSkip:        []string{"collector"},
		structsToSkip:     []string{"ServiceEntry", "Expression"},
		structsToNotAnon: []string{
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
			"UniqueId",
			"Id",
		},
		idRefFields: []string{
			"HostId",
			"OwnerId",
			"RealizationId",
			"ExternalId",
			"OwnerVmId",
			"SectionId",
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
		fieldsByRef: [][]string{
			{"TargetDisplayName", "TargetId", "DisplayName"},
		},
		fieldsToClear: []string{"ComputeIds"},
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
	}
}

func toAnonymizeFilter(user, structInstance interface{}) bool {
	return user.(*anonymizer).toAnonymizeFilter(structInstance)
}
func collectIDsToKeep(user, structInstance interface{}) {
	user.(*anonymizer).collectIDsToKeep(structInstance)
}
func anonymizeIDs(user, structInstance interface{}) {
	user.(*anonymizer).anonymizeIDs(structInstance)
}
func anonymizeRefs(user, structInstance interface{}) {
	user.(*anonymizer).anonymizeRefs(structInstance)
}
func anonymizeFields(user, structInstance interface{}) {
	user.(*anonymizer).anonymizeFields(structInstance)
}
func collectPaths(user, structInstance interface{}) {
	user.(*anonymizer).collectPaths(structInstance)
}
func anonymizePaths(user, structInstance interface{}) {
	user.(*anonymizer).anonymizePaths(structInstance)
}

////////////////////////////////////////////////////////////////////////////////////////
