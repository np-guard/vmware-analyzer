package model

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/endpoints"
	nsx "github.com/np-guard/vmware-analyzer/pkg/analyzer/generated"
)

type topology struct {
	segments      []*endpoints.Segment
	vmSegments    map[endpoints.EP][]*endpoints.Segment
	externalBlock *netset.IPBlock
}

func newTopology() *topology {
	return &topology{vmSegments: map[endpoints.EP][]*endpoints.Segment{}, externalBlock: netset.GetCidrAll()}
}

func (p *NSXConfigParser) getTopology() (err error) {
	p.topology = newTopology()
	for i := range p.rc.SegmentList {
		segResource := &p.rc.SegmentList[i]
		if len(segResource.SegmentPorts) == 0 && len(segResource.Subnets) == 0 {
			continue
		}
		subnetsNetworks := common.CustomStrSliceToStrings(segResource.Subnets, func(subnet nsx.SegmentSubnet) string { return *subnet.Network })
		block, err := netset.IPBlockFromCidrList(subnetsNetworks)
		if err != nil {
			return err
		}
		segment := endpoints.NewSegment(*segResource.DisplayName, block)		
		for pi := range segResource.SegmentPorts {
			att := *segResource.SegmentPorts[pi].Attachment.Id
			vni := p.rc.GetVirtualNetworkInterfaceByPort(att)
			if vm, ok := p.configRes.vmsMap[*vni.OwnerVmId]; ok {
				p.topology.vmSegments[vm] = append(p.topology.vmSegments[vm], segment)
				segment.VMs = append(segment.VMs, vm)
			}
		}
		p.topology.externalBlock = p.topology.externalBlock.Subtract(segment.Block)
		p.topology.segments = append(p.topology.segments, segment)
	}
	return nil
}
