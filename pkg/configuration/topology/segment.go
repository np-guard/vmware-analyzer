package topology

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

const (
	// NSX segment types
	vlan    = "Vlan"
	overlay = "Overlay"
)

/*
var enumValues_SegmentType = []interface{}{
	"ROUTED",
	"EXTENDED",
	"ROUTED_AND_EXTENDED",
	"DISCONNECTED",
}
*/

/*
vephere api indication for nsx ports (per vms on NSX segments ):
from vsphere api, running   ` govc collect -type="n"  ` ,
returns details of DistributedVirtualPortgroup , both for vsphere and for nsx.
portKeys for each DistributedVirtualPortgroup is of a different type.
for vsphere it is integer ports, and for nsx it is a list of UIDs.

collecting here the same nsx UIDs for each segment's ports.

*/

// Segment captures NSX Segment properties
type Segment struct {
	name           string
	uid            string
	cidrs          []string
	vms            []*VM
	origSegmentObj *collector.Segment
	overlayOrVlan  string
	vlanIDs        []string
	segmentType    string // routed / disconnected / extended / routed_and_extended
	ports          []*segmentPort
}

// segmentPort captures NSX segment ports relevant properties
type segmentPort struct {
	uid        string
	name       string
	inferredVM *VM
}

func NewSegment(origSegmentObj *collector.Segment, vms []*VM) *Segment {
	res := &Segment{origSegmentObj: origSegmentObj, vms: vms}
	res.name = *origSegmentObj.DisplayName
	res.uid = *origSegmentObj.UniqueId
	res.cidrs = common.CustomStrSliceToStrings(origSegmentObj.Subnets, func(s nsx.SegmentSubnet) string { return *s.Network })
	if len(origSegmentObj.VlanIds) > 0 {
		res.overlayOrVlan = vlan
		res.vlanIDs = origSegmentObj.VlanIds
	} else if origSegmentObj.OverlayId != nil || origSegmentObj.ConnectivityPath != nil {
		res.overlayOrVlan = overlay
	}
	if origSegmentObj.Type != nil {
		res.segmentType = string(*origSegmentObj.Type)
	}
	// add segment ports with relevant properties
	for i := range origSegmentObj.SegmentPorts {
		port := &origSegmentObj.SegmentPorts[i]
		res.ports = append(res.ports, &segmentPort{
			uid:        *port.UniqueId,
			name:       *port.DisplayName,
			inferredVM: portToVM(*port.DisplayName, vms)})
	}
	return res
}

func portToVM(portName string, segmentVMs []*VM) *VM {
	for _, vm := range segmentVMs {
		expectedPrefix := vm.Name() + "."
		if strings.HasPrefix(portName, expectedPrefix) {
			return vm
		}
	}
	return nil
}

func (s *Segment) Name() string {
	return s.name
}

func (s *Segment) ID() string {
	return s.uid
}

func (s *Segment) CIDRs() string {
	return strings.Join(s.cidrs, common.CommaSeparator)
}

func (s *Segment) VMs() []*VM {
	return s.vms
}

func (s *Segment) OverlayOrVlan() string {
	return s.overlayOrVlan
}

func (s *Segment) VlanIDs() string {
	return strings.Join(s.vlanIDs, common.CommaSeparator)
}

func (s *Segment) SegmentType() string {
	return s.segmentType
}

type PortDetails struct {
	SegmentName string
	PortName    string
	PortUID     string
	VMName      string
}

func (p *PortDetails) ToStrSlice() []string {
	return []string{p.SegmentName, p.PortName, p.PortUID, p.VMName}
}

func (s *Segment) PortsDetails() (res []*PortDetails) {
	for _, p := range s.ports {
		vmName := ""
		if p.inferredVM != nil {
			vmName = p.inferredVM.Name()
		}
		res = append(res, &PortDetails{s.name, p.name, p.uid, vmName})
	}
	return res
}
