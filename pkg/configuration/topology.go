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
	Segments           []*topology.Segment
	VmSegments         map[topology.Endpoint][]*topology.Segment
	AllRuleIPBlocks    map[string]*topology.RuleIPBlock              // a map from the ip string,to the block
	RuleBlockPerEP     map[topology.Endpoint][]*topology.RuleIPBlock // map from ep to its blocks
	allIPBlock         *netset.IPBlock                               // the union of segments and rule path IPs
	allInternalIPBlock *netset.IPBlock
	AllExternalIPBlock *netset.IPBlock
}

func (t *nsxTopology) addIPBlock(ip string) {
	ipb, err := common.IPBlockFromCidrOrAddressOrIPRange(ip)
	if err != nil {
		logging.Debugf("Failed to parse IP string %s, ignoring this IP", ip)
		return
	}

	t.allIPBlock = t.allIPBlock.Union(ipb)
	t.AllRuleIPBlocks[ip] = topology.NewRuleIPBlock(ip, ipb)
}

func newTopology() *nsxTopology {
	return &nsxTopology{
		VmSegments:         map[topology.Endpoint][]*topology.Segment{},
		AllRuleIPBlocks:    map[string]*topology.RuleIPBlock{},
		RuleBlockPerEP:     map[topology.Endpoint][]*topology.RuleIPBlock{},
		allIPBlock:         netset.NewIPBlock(),
		allInternalIPBlock: netset.NewIPBlock(),
	}
}

func (p *nsxConfigParser) getTopology() (err error) {
	p.configRes.Topology = newTopology()
	if err := p.getSegments(); err != nil {
		return err
	}
	p.getAllRulesIPBlocks()
	p.getRuleBlocksVMs()
	p.getExternalIPs()
	return nil
}

func (p *nsxConfigParser) getSegments() (err error) {
	p.configRes.PathToSegmentsMap = map[string]*topology.Segment{}
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
				p.configRes.Topology.VmSegments[vm] = append(p.configRes.Topology.VmSegments[vm], segment)
				segment.VMs = append(segment.VMs, vm)
			}
		}
		p.configRes.Topology.allInternalIPBlock = p.configRes.Topology.allInternalIPBlock.Union(segment.Block)
		p.configRes.Topology.allIPBlock = p.configRes.Topology.allIPBlock.Union(segment.Block)
		p.configRes.Topology.Segments = append(p.configRes.Topology.Segments, segment)
		if segResource.Path != nil {
			p.configRes.PathToSegmentsMap[*segResource.Path] = segment
		}
	}
	return nil
}

func (p *nsxConfigParser) getAllRulesIPBlocks() {
	allIPs := []string{} // allIPs will be populated with hard-coded IP Addresses from "paths" in src/dst of DFW rules
	// paths in DFW rules src/dst elements may contain direct IP addresses
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
		p.configRes.Topology.addIPBlock(ip)
	}

	// add also groups of type "IP addresses" rather than generic
	for _, group := range p.allGroups {
		if group.IsGroupTypeIPAddress() {
			for _, ip := range group.AddressMembers {
				p.configRes.Topology.addIPBlock(string(ip))
			}
		}
	}
}

// creating external endpoints
func (p *nsxConfigParser) getExternalIPs() {
	// calc external range:
	p.configRes.Topology.AllExternalIPBlock = p.configRes.Topology.allIPBlock.Subtract(p.configRes.Topology.allInternalIPBlock)
	if p.configRes.Topology.AllExternalIPBlock.IsEmpty() {
		return
	}
	// collect all the blocks:
	exBlocks := make([]*netset.IPBlock, len(p.configRes.Topology.AllRuleIPBlocks))
	for i, ruleBlock := range slices.Collect(maps.Values(p.configRes.Topology.AllRuleIPBlocks)) {
		ruleBlock.ExternalRange = ruleBlock.Block.Intersect(p.configRes.Topology.AllExternalIPBlock)
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
	for _, ruleBlock := range p.configRes.Topology.AllRuleIPBlocks {
		for _, externalIP := range p.configRes.externalIPs {
			if externalIP.(*topology.ExternalIP).Block.IsSubset(ruleBlock.Block) {
				ruleBlock.ExternalIPs = append(ruleBlock.ExternalIPs, externalIP)
				p.configRes.Topology.RuleBlockPerEP[externalIP] = append(p.configRes.Topology.RuleBlockPerEP[externalIP], ruleBlock)
			}
		}
	}
}

func (p *nsxConfigParser) getRuleBlocksVMs() {
	// iterate over VMs, look if the vm address is in the block:
	allCidrBlock := p.configRes.Topology.AllRuleIPBlocks[netset.CidrAll]
	for _, vm := range p.configRes.VMs {
		addresses := vm.(*topology.VM).IPAddresses()
		if len(addresses) == 0 && allCidrBlock != nil {
			allCidrBlock.VMs = append(allCidrBlock.VMs, vm)
		}
		for _, address := range addresses {
			parsedAddress, err := iIPBlockFromIPAddress(address)
			if err != nil {
				logging.Debugf("ignoring VM's address string: unsupported address %s of VM %s", address, vm.Name())
				continue
			}
			p.configRes.Topology.allInternalIPBlock = p.configRes.Topology.allInternalIPBlock.Union(parsedAddress)
			p.configRes.Topology.allIPBlock = p.configRes.Topology.allIPBlock.Union(parsedAddress)
			for _, block := range p.configRes.Topology.AllRuleIPBlocks {
				if parsedAddress.IsSubset(block.Block) {
					block.VMs = append(block.VMs, vm)
					p.configRes.Topology.RuleBlockPerEP[vm] = append(p.configRes.Topology.RuleBlockPerEP[vm], block)
				}
			}
		}
	}
	// iterate over segments, if segment is in the block, add all its vms
	for _, block := range p.configRes.Topology.AllRuleIPBlocks {
		for _, segment := range p.configRes.Topology.Segments {
			if !segment.Block.IsEmpty() && segment.Block.IsSubset(block.Block) {
				block.VMs = append(block.VMs, segment.VMs...)
				block.SegmentsVMs = append(block.SegmentsVMs, segment.VMs...)
				block.Segments = append(block.Segments, segment)
				for _, vm := range segment.VMs {
					p.configRes.Topology.RuleBlockPerEP[vm] = append(p.configRes.Topology.RuleBlockPerEP[vm], block)
				}
			}
		}
		block.VMs = common.SliceCompact(block.VMs)
	}
	for _, vm := range p.configRes.VMs {
		p.configRes.Topology.RuleBlockPerEP[vm] = common.SliceCompact(p.configRes.Topology.RuleBlockPerEP[vm])
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
