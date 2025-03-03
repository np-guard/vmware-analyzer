package configuration

import (
	"maps"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
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
	if err := p.getSegments(); err != nil {
		return err
	}
	p.getRulesIPBlocks()
	p.getExternalIPs()
	// todo - calc VMs of the block
	return nil
}

func (p *nsxConfigParser) getSegments() (err error) {
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

func (p *nsxConfigParser) getRulesIPBlocks() {
	allIPs := []string{}
	// collect all the paths from the rules:
	for i := range p.rc.DomainList {
		domainRsc := p.rc.DomainList[i].Resources
		for j := range domainRsc.SecurityPolicyList {
			secPolicy := &domainRsc.SecurityPolicyList[j]
			rules := secPolicy.Rules
			for i := range rules {
				rule := &rules[i]
				allIPs = append(allIPs, rule.DestinationGroups...)
				allIPs = append(allIPs, rule.SourceGroups...)
			}
		}
	}
	// remove ANY and paths to groups:
	slices.Sort(allIPs)
	allIPs = slices.Compact(allIPs)
	allIPs = slices.DeleteFunc(allIPs, func(path string) bool { return path == anyStr || slices.Contains(p.allGroupsPaths, path) })
	// create the blocks:
	for _, ip := range allIPs {
		block, err := netset.IPBlockFromCidrOrAddress(ip)
		if err != nil {
			block, err = netset.IPBlockFromIPRangeStr(ip)
		}
		if err != nil {
			logging.Warnf("Fail to parse IP %s, ignoring ip", ip)
			continue
		}
		p.allRuleIPBlocks[ip] = topology.NewRuleIPBlock(ip, block)
	}
}

// creating external endpoints
func (p *nsxConfigParser) getExternalIPs() {
	// collect all the blocks:
	exBlocks := make([]*netset.IPBlock, len(p.allRuleIPBlocks))
	for i, ruleBlock := range slices.Collect(maps.Values(p.allRuleIPBlocks)) {
		exBlocks[i] = ruleBlock.Block.Intersect(p.topology.externalBlock)
	}
	// creating disjoint blocks:
	disjointBlocks := netset.DisjointIPBlocks(exBlocks, nil)
	p.configRes.externalIPs = make([]topology.Endpoint, len(netset.DisjointIPBlocks(exBlocks, nil)))
	// create external IP per disjoint block:
	for i, disjointBlock := range disjointBlocks {
		p.configRes.externalIPs[i] = topology.NewExternalIP(disjointBlock)
	}
	// keep the external ips of each block:
	for _, ruleBlock := range p.allRuleIPBlocks {
		for _, externalIP := range p.configRes.externalIPs {
			if externalIP.(*topology.ExternalIP).Block.IsSubset(ruleBlock.Block) {
				ruleBlock.ExternalIPs = append(ruleBlock.ExternalIPs, externalIP)
			}
		}
	}
}
