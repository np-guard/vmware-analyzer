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
	segments        []*topology.Segment
	vmSegments      map[topology.Endpoint][]*topology.Segment
	allRuleIPBlocks map[string]*topology.RuleIPBlock // a map from the ip string,to the block
	externalBlock   *netset.IPBlock
}

func newTopology() *nsxTopology {
	return &nsxTopology{
		vmSegments:      map[topology.Endpoint][]*topology.Segment{},
		externalBlock:   netset.GetCidrAll(),
		allRuleIPBlocks: map[string]*topology.RuleIPBlock{},
	}
}

func (p *nsxConfigParser) getTopology() (err error) {
	p.topology = newTopology()
	if err := p.getSegments(); err != nil {
		return err
	}
	p.getAllRulesIPBlocks()
	p.getExternalIPs()
	p.getRuleBlocksVMs()
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

		segment := topology.NewSegment(*segResource.DisplayName, block, subnetsNetworks)

		for pi := range segResource.SegmentPorts {
			att := *segResource.SegmentPorts[pi].Attachment.Id
			vni := p.rc.GetVirtualNetworkInterfaceByPort(att)
			if vm, ok := p.configRes.VMsMap[*vni.OwnerVmId]; ok {
				p.topology.vmSegments[vm] = append(p.topology.vmSegments[vm], segment)
				segment.VMs = append(segment.VMs, vm)
			}
		}
		p.topology.externalBlock = p.topology.externalBlock.Subtract(segment.Block)
		p.topology.segments = append(p.topology.segments, segment)
	}
	return nil
}

func (p *nsxConfigParser) getAllRulesIPBlocks() {
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
	// remove duplications, "ANY" and paths to groups:
	allIPs = common.SliceCompact(allIPs)
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
		p.topology.allRuleIPBlocks[ip] = topology.NewRuleIPBlock(ip, block)
	}
}

// creating external endpoints
func (p *nsxConfigParser) getExternalIPs() {
	// collect all the blocks:
	exBlocks := make([]*netset.IPBlock, len(p.topology.allRuleIPBlocks))
	for i, ruleBlock := range slices.Collect(maps.Values(p.topology.allRuleIPBlocks)) {
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
	for _, ruleBlock := range p.topology.allRuleIPBlocks {
		for _, externalIP := range p.configRes.externalIPs {
			if externalIP.(*topology.ExternalIP).Block.IsSubset(ruleBlock.Block) {
				ruleBlock.ExternalIPs = append(ruleBlock.ExternalIPs, externalIP)
				p.configRes.RuleBlockPerEP[externalIP] = append(p.configRes.RuleBlockPerEP[externalIP], ruleBlock)
			}
		}
	}
}

func (p *nsxConfigParser) getRuleBlocksVMs() {
	for _, block := range p.topology.allRuleIPBlocks {
		// iterate over VMs, look if the vm address is in the block:
		for _, vm := range p.configRes.VMs {
			for _, address := range vm.(*topology.VM).IPAddresses() {
				address, err := netset.IPBlockFromIPAddress(address)
				if err != nil {
					logging.Warnf("Could not resolve address %s of vm %s", address, vm.Name())
					continue
				}
				if address.IsSubset(block.Block) {
					block.VMs = append(block.VMs, vm)
					p.configRes.RuleBlockPerEP[vm] = append(p.configRes.RuleBlockPerEP[vm], block)
				}
			}
		}
		// iterate over segments, if segment is in the block, add all its vms 
		for _, segment := range p.topology.segments {
			if segment.Block.IsSubset(block.Block) {
				block.VMs = append(block.VMs, segment.VMs...)
				for _, vm := range segment.VMs {
					p.configRes.RuleBlockPerEP[vm] = append(p.configRes.RuleBlockPerEP[vm], block)
				}
			}
		}
		block.VMs = common.SliceCompact(block.VMs)
	}
	for _, vm := range p.configRes.VMs {
		p.configRes.RuleBlockPerEP[vm] = common.SliceCompact(p.configRes.RuleBlockPerEP[vm])
	}
}
