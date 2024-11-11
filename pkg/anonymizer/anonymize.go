/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"strings"
)

func Anonymize(st structInstance) {
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
		theReferenceField: "Id",
		pkgsToSkip:        []string{"collector"},
		structsToSkip:     []string{"ServiceEntry", "Expression"},
		refStructs: map[string]string{
			"RealizedVirtualMachine": "VirtualMachine",
		},
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
			"ExternalId",
			"UniqueId",
			"Id",
		},
		idRefFields: []string{
			"RealizationId",
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
		fieldsToClear: []string{
			"ComputeIds",
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

func toAnonymizeFilter(user iteratorUser, structInstance structInstance) bool {
	return user.(*anonymizer).toAnonymizeFilter(structInstance)
}
func collectIDsToKeep(user iteratorUser, structInstance structInstance) {
	user.(*anonymizer).collectIDsToKeep(structInstance)
}
func anonymizeIDs(user iteratorUser, structInstance structInstance) {
	user.(*anonymizer).anonymizeIDs(structInstance)
}
func anonymizeRefs(user iteratorUser, structInstance structInstance) {
	user.(*anonymizer).anonymizeRefs(structInstance)
}
func anonymizeFields(user iteratorUser, structInstance structInstance) {
	user.(*anonymizer).anonymizeFields(structInstance)
}
func collectPaths(user iteratorUser, structInstance structInstance) {
	user.(*anonymizer).collectPaths(structInstance)
}
func anonymizePaths(user iteratorUser, structInstance structInstance) {
	user.(*anonymizer).anonymizePaths(structInstance)
}

////////////////////////////////////////////////////////////////////////////////////////
