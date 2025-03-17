package configuration

import (
	"slices"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

func filterResources(rc *collector.ResourcesContainerModel, VMs []string) {
	if len(VMs) == 0 {
		return
	}
	// removing vms from vm list:
	vmFilter := func(vm collector.VirtualMachine) bool {
		return vm.DisplayName == nil || vm.ExternalId == nil || !slices.Contains(VMs, *vm.DisplayName)
	}
	rc.VirtualMachineList = slices.DeleteFunc(rc.VirtualMachineList, vmFilter)
	vmIds := common.CustomStrSliceToStrings(rc.VirtualMachineList, func(vm collector.VirtualMachine) string { return *vm.ExternalId })
	// remove vnis from list:
	vniFilter := func(vni collector.VirtualNetworkInterface) bool {
		return !slices.Contains(vmIds, *vni.OwnerVmId)
	}
	rc.VirtualNetworkInterfaceList = slices.DeleteFunc(rc.VirtualNetworkInterfaceList, vniFilter)
	vnisAttIds := common.CustomStrSliceToStrings(rc.VirtualNetworkInterfaceList, func(vni collector.VirtualNetworkInterface) string { return *vni.LportAttachmentId })
	vmsAddresses := common.CustomStrsSliceToStrings(rc.VirtualNetworkInterfaceList, func(vni collector.VirtualNetworkInterface) []string {
		return common.CustomStrsSliceToStrings(vni.IpAddressInfo, func(info nsx.IpAddressInfo) []string {
			return common.CustomStrSliceToStrings(info.IpAddresses, func(ip nsx.IPAddress) string { return string(ip) })
		})
	})

	// remove segment ports:
	portFilter := func(port collector.SegmentPort) bool {
		return !slices.Contains(vnisAttIds, *port.Attachment.Id)
	}
	for i := range rc.SegmentList {
		segment := &rc.SegmentList[i]
		segment.SegmentPorts = slices.DeleteFunc(segment.SegmentPorts, portFilter)
	}
	//remove empty segments:
	segmentFilter := func(segment collector.Segment) bool {
		return len(segment.SegmentPorts) == 0
	}
	rc.SegmentList = slices.DeleteFunc(rc.SegmentList, segmentFilter)

	// remove filtered vms, vnis and addresses from groups:
	groupVmFilter := func(vm collector.RealizedVirtualMachine) bool {
		return vm.Id == nil || !slices.Contains(vmIds, *vm.Id)
	}
	addressFilter := func(ip nsx.IPElement) bool {
		return !slices.Contains(vmsAddresses, string(ip))
	}
	allGroupPaths := []string{}
	allRemainGroupPaths := []string{}
	for i := range rc.DomainList {
		domainRsc := &rc.DomainList[i].Resources
		allGroupPaths = append(allGroupPaths, common.CustomStrSliceToStrings(domainRsc.GroupList, func(group collector.Group) string { return *group.Path })...)
		for j := range domainRsc.GroupList {
			domainRsc.GroupList[j].VMMembers = slices.DeleteFunc(domainRsc.GroupList[j].VMMembers, groupVmFilter)
			domainRsc.GroupList[j].VIFMembers = slices.DeleteFunc(domainRsc.GroupList[j].VIFMembers, vniFilter)
			domainRsc.GroupList[j].AddressMembers = slices.DeleteFunc(domainRsc.GroupList[j].AddressMembers, addressFilter)
		}
		// remove empty groups:
		groupFilter := func(group collector.Group) bool {
			return len(group.VMMembers) == 0 && len(group.AddressMembers) == 0
		}
		domainRsc.GroupList = slices.DeleteFunc(domainRsc.GroupList, groupFilter)
		allRemainGroupPaths = append(allRemainGroupPaths, common.CustomStrSliceToStrings(domainRsc.GroupList, func(group collector.Group) string { return *group.Path })...)
	}
	// handling groups:
	groupPathFilter := func(path string) bool {
		return slices.Contains(allGroupPaths, path) && !slices.Contains(allRemainGroupPaths, path)
	}
	ruleFilter := func(rule collector.Rule) bool {
		return len(rule.SourceGroups) == 0 || len(rule.DestinationGroups) == 0 || len(rule.Scope) == 0
	}
	for i := range rc.DomainList {
		domainRsc := rc.DomainList[i].Resources
		for j := range domainRsc.SecurityPolicyList {
			secPolicy := &domainRsc.SecurityPolicyList[j]
			secPolicy.Scope = slices.DeleteFunc(secPolicy.Scope, groupPathFilter)
			for i := range secPolicy.Rules {
				rule := &secPolicy.Rules[i]
				// remove paths from rules:
				rule.SourceGroups = slices.DeleteFunc(rule.SourceGroups, groupPathFilter)
				rule.DestinationGroups = slices.DeleteFunc(rule.DestinationGroups, groupPathFilter)
				rule.Scope = slices.DeleteFunc(rule.Scope, groupPathFilter)
				// todo - is the following good enough:
				if len(rule.SourceGroups) == 0 && rule.SourcesExcluded {
					rule.SourceGroups = []string{common.AnyStr}
					rule.SourcesExcluded = false
				}
				if len(rule.DestinationGroups) == 0 && rule.DestinationsExcluded {
					rule.DestinationGroups = []string{common.AnyStr}
					rule.DestinationsExcluded = false
				}
			}
			// remove empty rules:
			secPolicy.Rules = slices.DeleteFunc(secPolicy.Rules, ruleFilter)
		}
	}
}
