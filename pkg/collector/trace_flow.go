package collector

import (
	"encoding/json"
	"fmt"

	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	traceFlowQuery               = "policy/api/v1/infra/traceflows/%s"
	getTraceFlowObservationQuery = "policy/api/v1/infra/traceflows/%s/observations"
)

func traceFlow(resources *ResourcesContainerModel, server ServerData) (string, error) {
	srcIp := "192.168.1.1"
	dstIp := "192.168.1.2"
	traceFlowName := "traceFlowUniqName" //todo
	srcVni := resources.GetVirtualNetworkInterfaceByAddress(srcIp)
	dstVni := resources.GetVirtualNetworkInterfaceByAddress(dstIp)
	if srcVni == nil {
		return "", fmt.Errorf("src does not exist")
	}
	if dstVni == nil {
		return "", fmt.Errorf("dst does not exist")
	}
	if srcVni.LportAttachmentId == nil {
		return "", fmt.Errorf("src does not have port")
	}
	port := resources.GetSegmentPort(*srcVni.LportAttachmentId)

	traceReq := &TraceflowConfig{}
	traceReq.SourceId = port.UniqueId
	traceReq.Packet = &nsx.FieldsPacketData{}
	traceReq.Packet.EthHeader = &nsx.EthernetHeader{SrcMac: srcVni.MacAddress, DstMac: dstVni.MacAddress}
	srcIPv4 := nsx.IPAddress(srcIp)
	dstIPv4 := nsx.IPAddress(dstIp)
	traceReq.Packet.IpHeader = &nsx.Ipv4Header{SrcIp: &srcIPv4, DstIp: &dstIPv4}
	traceReq.Packet.TransportHeader = &nsx.TransportProtocolHeader{}
	traceReq.Packet.TransportHeader.IcmpEchoRequestHeader = &nsx.IcmpEchoRequestHeader{}
	routed := bool(true)
	traceReq.Packet.Routed = &routed
	b, _ := json.Marshal(traceReq)
	json.Unmarshal(b, &traceReq)
	PutResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName), traceReq)
	return traceFlowName, nil
}

func deleteTraceFlow(server ServerData, traceFlowName string) error {
	return DeleteResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName))
}
func traceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	var t TraceFlowObservations
	err := collectResult(server, fmt.Sprintf(getTraceFlowObservationQuery, traceFlowName), &t)
	return t, err
}
