package configuration

import (
	"fmt"
	"maps"
	"net"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

type nsxTopology struct {
	segments           []*topology.Segment
	vmSegments         map[topology.Endpoint][]*topology.Segment
	allRuleIPBlocks    map[string]*topology.RuleIPBlock              // a map from the ip string,to the block
	ruleBlockPerEP     map[topology.Endpoint][]*topology.RuleIPBlock // map from vm to its blocks
	allIPBlock         *netset.IPBlock                               // the union of segments and rule path IPs
	allInternalIPBlock *netset.IPBlock
	allExternalIPBlock *netset.IPBlock
}

func newTopology() *nsxTopology {
	return &nsxTopology{
		vmSegments:         map[topology.Endpoint][]*topology.Segment{},
		allRuleIPBlocks:    map[string]*topology.RuleIPBlock{},
		ruleBlockPerEP:     map[topology.Endpoint][]*topology.RuleIPBlock{},
		allIPBlock:         netset.NewIPBlock(),
		allInternalIPBlock: netset.NewIPBlock(),
	}
}

func (p *nsxConfigParser) getTopology() (err error) {
	p.configRes.topology = newTopology()
	if err := p.getSegments(); err != nil {
		return err
	}
	p.getAllRulesIPBlocks()
	p.getRuleBlocksVMs()
	p.getExternalIPs()
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
				p.configRes.topology.vmSegments[vm] = append(p.configRes.topology.vmSegments[vm], segment)
				segment.VMs = append(segment.VMs, vm)
			}
		}
		p.configRes.topology.allInternalIPBlock = p.configRes.topology.allInternalIPBlock.Union(segment.Block)
		p.configRes.topology.allIPBlock = p.configRes.topology.allIPBlock.Union(segment.Block)
		p.configRes.topology.segments = append(p.configRes.topology.segments, segment)
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
			logging.Debugf("Fail to parse IP %s, ignoring ip", ip)
			continue
		}
		p.configRes.topology.allIPBlock = p.configRes.topology.allIPBlock.Union(block)
		p.configRes.topology.allRuleIPBlocks[ip] = topology.NewRuleIPBlock(ip, block)
	}
}

// creating external endpoints
func (p *nsxConfigParser) getExternalIPs() {
	// calc external range:
	p.configRes.topology.allExternalIPBlock = p.configRes.topology.allIPBlock.Subtract(p.configRes.topology.allInternalIPBlock)
	if p.configRes.topology.allExternalIPBlock.IsEmpty() {
		return
	}
	// collect all the blocks:
	exBlocks := make([]*netset.IPBlock, len(p.configRes.topology.allRuleIPBlocks))
	for i, ruleBlock := range slices.Collect(maps.Values(p.configRes.topology.allRuleIPBlocks)) {
		ruleBlock.ExternalRange = ruleBlock.Block.Intersect(p.configRes.topology.allExternalIPBlock)
		exBlocks[i] = ruleBlock.ExternalRange
	}
	// creating disjoint blocks:
	disjointBlocks := netset.DisjointIPBlocks(exBlocks, nil)
	p.configRes.externalIPs = make([]topology.Endpoint, len(netset.DisjointIPBlocks(exBlocks, nil)))
	// create external IP per disjoint block:
	for i, disjointBlock := range disjointBlocks {
		p.configRes.externalIPs[i] = topology.NewExternalIP(disjointBlock)
	}
	// keep the external ips of each block:
	for _, ruleBlock := range p.configRes.topology.allRuleIPBlocks {
		for _, externalIP := range p.configRes.externalIPs {
			if externalIP.(*topology.ExternalIP).Block.IsSubset(ruleBlock.Block) {
				ruleBlock.ExternalIPs = append(ruleBlock.ExternalIPs, externalIP)
				p.configRes.topology.ruleBlockPerEP[externalIP] = append(p.configRes.topology.ruleBlockPerEP[externalIP], ruleBlock)
			}
		}
	}
}

func (p *nsxConfigParser) getRuleBlocksVMs() {
	// iterate over VMs, look if the vm address is in the block:
	for _, vm := range p.configRes.VMs {
		for _, address := range vm.(*topology.VM).IPAddresses() {
			address, err := iIPBlockFromIPAddress(address)
			if err != nil {
				logging.Debugf("Could not resolve address %s of vm %s", address, vm.Name())
				continue
			}
			p.configRes.topology.allInternalIPBlock = p.configRes.topology.allInternalIPBlock.Union(address)
			for _, block := range p.configRes.topology.allRuleIPBlocks {
				if address.IsSubset(block.Block) {
					block.VMs = append(block.VMs, vm)
					p.configRes.topology.ruleBlockPerEP[vm] = append(p.configRes.topology.ruleBlockPerEP[vm], block)
				}
			}
		}
	}
	// iterate over segments, if segment is in the block, add all its vms
	for _, block := range p.configRes.topology.allRuleIPBlocks {
		for _, segment := range p.configRes.topology.segments {
			if !segment.Block.IsEmpty() && segment.Block.IsSubset(block.Block) {
				block.VMs = append(block.VMs, segment.VMs...)
				block.SegmentsVMs = append(block.SegmentsVMs, segment.VMs...)
				block.Segments = append(block.Segments, segment)
				for _, vm := range segment.VMs {
					p.configRes.topology.ruleBlockPerEP[vm] = append(p.configRes.topology.ruleBlockPerEP[vm], block)
				}
			}
		}
		block.VMs = common.SliceCompact(block.VMs)
	}
	for _, vm := range p.configRes.VMs {
		p.configRes.topology.ruleBlockPerEP[vm] = common.SliceCompact(p.configRes.topology.ruleBlockPerEP[vm])
	}
}

// tmp function till netset is fixed:
func iIPBlockFromIPAddress(ipAddress string) (*netset.IPBlock, error) {
	startIP := net.ParseIP(ipAddress)
	if startIP == nil || startIP.To4() == nil {
		return nil, fmt.Errorf("%s is not a valid IPv4 address", ipAddress)
	}
	return netset.IPBlockFromIPAddress(ipAddress)
}
