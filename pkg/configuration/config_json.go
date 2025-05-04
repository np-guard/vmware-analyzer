package configuration

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
)

// configInfo captures config details in relevant hierarchy for JSON output
type configInfo struct {
	Segments   []segmentInfo `json:"segments"`
	VMs        []vmInfo      `json:"vms"`
	T1Gateways []t1Info      `json:"t1_gateways"`
	T0Gateways []t0Info      `json:"t0_gateways"`
}

type vmInfo struct {
	Name        string   `json:"name"`
	UID         string   `json:"uid"`
	IPAddresses string   `json:"ip_addresses,omitempty"`
	Tags        []string `json:"tags"`
	Groups      []string `json:"groups"`
}

type segmentInfo struct {
	Name     string            `json:"name"`
	UID      string            `json:"uid"`
	CIDRs    string            `json:"cidrs"`
	Category string            `json:"category"`
	Type     string            `json:"type"`
	VlanIDs  string            `json:"vlan_ids,omitempty"`
	Ports    []segmentPortInfo `json:"ports"`
}

type segmentPortInfo struct {
	Name   string `json:"name"`
	UID    string `json:"uid"`
	VMName string `json:"vm_name,omitempty"`
}

type t1Info struct {
	Name     string   `json:"name"`
	Segments []string `json:"segments"`
}

type t0Info struct {
	Name        string   `json:"name"`
	Segments    []string `json:"segments"`
	T1sAttached []string `json:"t1s_attached"`
}

func (c *Config) buildConfigInfo() {
	c.configSummary = &configInfo{}
	for _, s := range c.segments {
		segInfo := segmentInfo{
			Name:     s.Name(),
			UID:      s.ID(),
			CIDRs:    s.CIDRs(),
			Category: s.OverlayOrVlan(),
			Type:     s.SegmentType(),
			VlanIDs:  s.VlanIDs(),
		}
		portsDetails := s.PortsDetails()
		for _, p := range portsDetails {
			portInfo := segmentPortInfo{Name: p.PortName, UID: p.PortUID, VMName: p.VMName}
			segInfo.Ports = append(segInfo.Ports, portInfo)
		}
		c.configSummary.Segments = append(c.configSummary.Segments, segInfo)
	}

	for _, v := range c.VMs {
		vmGroupsList := []string{}
		groups, ok := c.GroupsPerVM[v]
		if ok {
			vmGroupsList = common.CustomStrSliceToStrings(groups, func(g *collector.Group) string { return *g.DisplayName })
		}

		c.configSummary.VMs = append(c.configSummary.VMs, vmInfo{
			Name:        v.Name(),
			UID:         v.ID(),
			IPAddresses: v.IPAddressesStr(),
			Tags:        v.Tags(),
			Groups:      vmGroupsList,
		})
	}

	for i := range c.OrigNSXResources.Tier1List {
		t1 := &c.OrigNSXResources.Tier1List[i]
		t1Segments := c.OrigNSXResources.GetSegmentsOfTier1(t1)
		t1Obj := t1Info{
			Name: *t1.DisplayName,
			Segments: common.CustomStrSliceToStrings(t1Segments, func(s *collector.Segment) string {
				if s.DisplayName != nil {
					return *s.DisplayName
				}
				return ""
			}),
		}
		c.configSummary.T1Gateways = append(c.configSummary.T1Gateways, t1Obj)
	}

	for i := range c.OrigNSXResources.Tier0List {
		t0 := &c.OrigNSXResources.Tier0List[i]
		t0Segments := c.OrigNSXResources.GetSegmentsOfTier0(t0)
		attachedT1s := c.OrigNSXResources.GetT1sOfTier0(t0)
		t0Obj := t0Info{
			Name: *t0.DisplayName,
			Segments: common.CustomStrSliceToStrings(t0Segments, func(s *collector.Segment) string {
				if s.DisplayName != nil {
					return *s.DisplayName
				}
				return ""
			}),
			T1sAttached: common.CustomStrSliceToStrings(attachedT1s, func(s *collector.Tier1) string {
				if s.DisplayName != nil {
					return *s.DisplayName
				}
				return ""
			}),
		}
		c.configSummary.T0Gateways = append(c.configSummary.T0Gateways, t0Obj)
	}
}

func (c *Config) TopologyToJSON() (string, error) {
	c.buildConfigInfo()
	return common.MarshalJSON(c.configSummary)
}
