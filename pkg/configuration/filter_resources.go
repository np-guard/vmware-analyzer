package configuration

import (
	"slices"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

// filterResources modifies the input ResourcesContainerModel, by filtering all elements based on input vms names to filter;
func filterResources(rc *collector.ResourcesContainerModel, filterVMs []string) {
	if len(filterVMs) == 0 {
		return
	}
	rf := resourceFilter{rc: rc, filterVMs: filterVMs}
	rf.filterTopology()
	rf.filterGroups()
	rf.filterRules()
}

type resourceFilter struct {
	rc                  *collector.ResourcesContainerModel
	filterVMs           []string // the filter from the user
	vmIds               []string // the ids of the filtered the vms
	vnisAttIds          []string // the vni attach id fo the filtered vnis, use to filter the segment ports
	vmsAddresses        []string // the vm addresses of the filtered the vms
	allGroupPaths       []string // all the group paths
	allRemainGroupPaths []string // the filtered paths
}

func (f *resourceFilter) filterTopology() {
	// removing vms from vm list:
	f.rc.VirtualMachineList = slices.DeleteFunc(f.rc.VirtualMachineList, f.vmFilter)
	f.vmIds = common.CustomStrSliceToStrings(f.rc.VirtualMachineList, func(vm collector.VirtualMachine) string { return *vm.ExternalId })
	// remove vnis from list:
	f.rc.VirtualNetworkInterfaceList = slices.DeleteFunc(f.rc.VirtualNetworkInterfaceList, f.vniFilter)
	f.vnisAttIds = common.CustomStrSliceToStrings(f.rc.VirtualNetworkInterfaceList,
		func(vni collector.VirtualNetworkInterface) string { return *vni.LportAttachmentId })
	// remove segment ports:
	for i := range f.rc.SegmentList {
		segment := &f.rc.SegmentList[i]
		segment.SegmentPorts = slices.DeleteFunc(segment.SegmentPorts, f.portFilter)
	}
	// remove empty segments:
	f.rc.SegmentList = slices.DeleteFunc(f.rc.SegmentList, f.segmentFilter)
}

func (f *resourceFilter) filterGroups() {
	// calc addresses of all vms:
	f.vmsAddresses = common.CustomStrsSliceToStrings(f.rc.VirtualNetworkInterfaceList, func(vni collector.VirtualNetworkInterface) []string {
		return common.CustomStrsSliceToStrings(vni.IpAddressInfo, func(info nsx.IpAddressInfo) []string {
			return common.CustomStrSliceToStrings(info.IpAddresses, func(ip nsx.IPAddress) string { return string(ip) })
		})
	})
	// remove filtered vms, vnis and addresses from groups:
	for i := range f.rc.DomainList {
		domainRsc := &f.rc.DomainList[i].Resources
		f.allGroupPaths = append(f.allGroupPaths, common.CustomStrSliceToStrings(domainRsc.GroupList,
			func(group collector.Group) string { return *group.Path })...)
		for j := range domainRsc.GroupList {
			domainRsc.GroupList[j].VMMembers = slices.DeleteFunc(domainRsc.GroupList[j].VMMembers, f.groupVMFilter)
			domainRsc.GroupList[j].VIFMembers = slices.DeleteFunc(domainRsc.GroupList[j].VIFMembers, f.vniFilter)
			domainRsc.GroupList[j].AddressMembers = slices.DeleteFunc(domainRsc.GroupList[j].AddressMembers, f.addressFilter)
		}
		// remove empty groups:
		domainRsc.GroupList = slices.DeleteFunc(domainRsc.GroupList, f.groupFilter)
		f.allRemainGroupPaths = append(f.allRemainGroupPaths, common.CustomStrSliceToStrings(domainRsc.GroupList,
			func(group collector.Group) string { return *group.Path })...)
	}
}
func (f *resourceFilter) filterRules() {
	// handling rules:
	for i := range f.rc.DomainList {
		domainRsc := f.rc.DomainList[i].Resources
		for j := range domainRsc.SecurityPolicyList {
			secPolicy := &domainRsc.SecurityPolicyList[j]
			secPolicy.Scope = slices.DeleteFunc(secPolicy.Scope, f.groupPathFilter)
			for i := range secPolicy.Rules {
				rule := &secPolicy.Rules[i]
				// remove paths from rules:
				rule.SourceGroups = slices.DeleteFunc(rule.SourceGroups, f.groupPathFilter)
				rule.DestinationGroups = slices.DeleteFunc(rule.DestinationGroups, f.groupPathFilter)
				rule.Scope = slices.DeleteFunc(rule.Scope, f.groupPathFilter)
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
			secPolicy.Rules = slices.DeleteFunc(secPolicy.Rules, f.ruleFilter)
		}
	}
}

//nolint:gocritic // filter can not be on pointer
func (f *resourceFilter) vmFilter(vm collector.VirtualMachine) bool {
	return vm.DisplayName == nil || vm.ExternalId == nil || !slices.Contains(f.filterVMs, *vm.DisplayName)
}

//nolint:gocritic // filter can not be on pointer
func (f *resourceFilter) vniFilter(vni collector.VirtualNetworkInterface) bool {
	return !slices.Contains(f.vmIds, *vni.OwnerVmId)
}

//nolint:gocritic // filter can not be on pointer
func (f *resourceFilter) portFilter(port collector.SegmentPort) bool {
	return !slices.Contains(f.vnisAttIds, *port.Attachment.Id)
}

//nolint:gocritic // filter can not be on pointer
func (f *resourceFilter) groupFilter(group collector.Group) bool {
	return len(group.VMMembers) == 0 && len(group.AddressMembers) == 0
}

func (f *resourceFilter) groupPathFilter(path string) bool {
	return slices.Contains(f.allGroupPaths, path) && !slices.Contains(f.allRemainGroupPaths, path)
}

//nolint:gocritic // filter can not be on pointer
func (f *resourceFilter) ruleFilter(rule collector.Rule) bool {
	return len(rule.SourceGroups) == 0 || len(rule.DestinationGroups) == 0 || len(rule.Scope) == 0
}

//nolint:gocritic // filter can not be on pointer
func (f *resourceFilter) segmentFilter(segment collector.Segment) bool {
	return len(segment.SegmentPorts) == 0
}

//nolint:gocritic // filter can not be on pointer
func (f *resourceFilter) groupVMFilter(vm collector.RealizedVirtualMachine) bool {
	return vm.Id == nil || !slices.Contains(f.vmIds, *vm.Id)
}

func (f *resourceFilter) addressFilter(ip nsx.IPElement) bool {
	return !slices.Contains(f.vmsAddresses, string(ip))
}
