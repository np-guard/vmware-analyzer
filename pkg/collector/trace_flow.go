package collector

import (
	"encoding/json"
	"fmt"

	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

func traceFlow(resources *ResourcesContainerModel, server ServerData) error {
	srcIp := "192.168.1.1"
	dstIp := "192.168.1.2"
	traceFlowName := "traceFlowUniqName" //todo
	srcVni := resources.GetVirtualNetworkInterfaceByAddress(srcIp)
	dstVni := resources.GetVirtualNetworkInterfaceByAddress(dstIp)
	if srcVni == nil {
		return fmt.Errorf("src does not exist")
	}
	if dstVni == nil {
		return fmt.Errorf("dst does not exist")
	}
	if srcVni.LportAttachmentId == nil {
		return fmt.Errorf("src does not have port")
	}
	port := resources.GetSegmentPort(*srcVni.LportAttachmentId)

	traceReq := &TraceflowConfig{}
	traceReq.SourceId = port.UniqueId
	traceReq.Packet = &nsx.FieldsPacketData{}
	traceReq.Packet.EthHeader = &nsx.EthernetHeader{SrcMac: srcVni.MacAddress, DstMac: dstVni.MacAddress}
	// srcAdd, _ := netip.ParseAddr(srcIp)
	// dstAdd, _ := netip.ParseAddr(dstIp)
	// srcIPv4 := nsx.IPv4Address(srcAdd)
	// dstIPv4 := nsx.IPv4Address(dstAdd)
	srcIPv4 := nsx.IPv4Address(srcIp)
	dstIPv4 := nsx.IPv4Address(dstIp)
	traceReq.Packet.IpHeader = &nsx.Ipv4Header{SrcIp: &srcIPv4, DstIp: &dstIPv4}
	traceReq.Packet.TransportHeader = &nsx.TransportProtocolHeader{}
	traceReq.Packet.TransportHeader.IcmpEchoRequestHeader = &nsx.IcmpEchoRequestHeader{}
	routed := bool(true)
	traceReq.Packet.Routed = &routed
	b, _ := json.Marshal(traceReq)
	json.Unmarshal(b, &traceReq)
	req := "policy/api/v1/infra/traceflows/%s"
	PutResource(server, fmt.Sprintf(req, traceFlowName), traceReq)
	return nil
}
