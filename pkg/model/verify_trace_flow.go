package model

import (
	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type vmFilter func(vm *endpoints.VM) bool

func createTraceflows(resources *collector.ResourcesContainerModel,
	server collector.ServerData,
	config *config, vmFilter vmFilter) *collector.TraceFlows {
	traceFlows := collector.NewTraceflows(resources, server)
	for srcUID, srcVM := range config.vmsMap {
		if !vmFilter(srcVM) {
			continue
		}
		vmIPs := resources.GetVirtualMachineAddresses(srcUID)
		if len(vmIPs) == 0 {
			continue
		}
		srcIP := vmIPs[0]
		srcVni := resources.GetVirtualNetworkInterfaceByAddress(srcIP)
		if srcVni == nil {
			continue
		}
		port := resources.GetSegmentPort(*srcVni.LportAttachmentId)
		if port == nil {
			continue
		}
		for dstUID, dstVM := range config.vmsMap {
			if srcUID == dstUID {
				continue
			}
			if !vmFilter(dstVM) {
				continue
			}
			vmIPs := resources.GetVirtualMachineAddresses(dstUID)
			if len(vmIPs) == 0 {
				continue
			}
			dstIP := vmIPs[0]
			conn := config.analyzedConnectivity[srcVM][dstVM]
			// temp fix till analyze will consider topology:
			if !conn.IsEmpty() {
				dstVni := resources.GetVirtualNetworkInterfaceByAddress(dstIP)
				if dstVni == nil || !collector.IsConnected(resources, srcVni, dstVni) {
					conn = netset.NoTransports()
				}
			}
			createTraceFlowsForConn(traceFlows, srcIP, dstIP, conn)
		}
	}
	return traceFlows
}

func createTraceFlowsForConn(traceFlows *collector.TraceFlows, srcIP, dstIP string, conn *netset.TransportSet) {
	connString := conn.String()
	switch {
	case conn.IsAll(), conn.IsEmpty():
		// one check only using icmp
		traceFlows.AddTraceFlow(srcIP, dstIP, collector.TraceFlowProtocol{Protocol: collector.ProtocolICMP}, conn.IsAll(), connString)
	case conn.TCPUDPSet().IsAll() || conn.TCPUDPSet().IsEmpty():
		// one check for icmp, one for tcp/udp
		traceFlows.AddTraceFlow(srcIP, dstIP, collector.TraceFlowProtocol{Protocol: collector.ProtocolICMP}, conn.ICMPSet().IsAll(), connString)
		aPort := (netp.MaxPort + netp.MinPort) / 2
		defaultProtocol := collector.TraceFlowProtocol{Protocol: collector.ProtocolTCP, SrcPort: aPort, DstPort: aPort}
		traceFlows.AddTraceFlow(srcIP, dstIP, defaultProtocol, conn.TCPUDPSet().IsAll(), connString)
	default:
		// checking only tcp/udp, one allow, one deny
		allowConn := conn.TCPUDPSet()
		denyConn := netset.AllTCPUDPSet().Subtract(allowConn)
		traceFlows.AddTraceFlow(srcIP, dstIP, toTraceFlowProtocol(allowConn), true, connString)
		traceFlows.AddTraceFlow(srcIP, dstIP, toTraceFlowProtocol(denyConn), false, connString)
	}
}

func toTraceFlowProtocol(set *netset.TCPUDPSet) collector.TraceFlowProtocol {
	partition := set.Partitions()[0]
	protocol := collector.ProtocolUDP
	if partition.S1.Contains(netset.TCPCode) {
		protocol = collector.ProtocolTCP
	}
	srcPort := partition.S2.Min()
	dstPort := partition.S3.Min()
	return collector.TraceFlowProtocol{Protocol: protocol, SrcPort: int(srcPort), DstPort: int(dstPort)}
}

func compareConfigToTraceflows(
	resources *collector.ResourcesContainerModel,
	server collector.ServerData,
	vmFilter vmFilter) (*collector.TraceFlows, error) {
	config, err := configFromResourcesContainer(resources, nil)
	if err != nil {
		return nil, err
	}
	traceFlows := createTraceflows(resources, server, config, vmFilter)
	traceFlows.Execute()
	traceFlows.Summery()
	return traceFlows, nil
}
