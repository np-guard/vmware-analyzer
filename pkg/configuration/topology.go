package configuration

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

type nsxTopology struct {
	segments      []*topology.Segment
	vmSegments    map[topology.Endpoint][]*topology.Segment
	externalBlock *netset.IPBlock
}

func newTopology() *nsxTopology {
	return &nsxTopology{vmSegments: map[topology.Endpoint][]*topology.Segment{}, externalBlock: netset.GetCidrAll()}
}

func (p *nsxConfigParser) getTopology() (err error) {
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
		segment := topology.NewSegment(*segResource.DisplayName, block)
		for pi := range segResource.SegmentPorts {
			att := *segResource.SegmentPorts[pi].Attachment.Id
			vni := p.rc.GetVirtualNetworkInterfaceByPort(att)
			if vm, ok := p.configRes.VmsMap[*vni.OwnerVmId]; ok {
				p.topology.vmSegments[vm] = append(p.topology.vmSegments[vm], segment)
				segment.VMs = append(segment.VMs, vm)
			}
		}
		p.topology.externalBlock = p.topology.externalBlock.Subtract(segment.Block)
		p.topology.segments = append(p.topology.segments, segment)
	}
	return nil
}
