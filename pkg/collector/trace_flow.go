package collector

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	traceFlowsQuery              = "policy/api/v1/infra/traceflows"
	traceFlowQuery               = "policy/api/v1/infra/traceflows/%s"
	getTraceFlowObservationQuery = "policy/api/v1/infra/traceflows/%s/observations"
)
const (
	protocolTCP  = "tcp"
	protocolUDP  = "udp"
	protocolICMP = "icmp"
)

const (
	traceflowIDSize          = 5
	traceflowPoolingTime     = 3
	traceflowNumberOfPooling = 10
)

type traceFlowProtocol struct {
	SrcPort  int `json:"src_port,omitempty"`
	DstPort  int `json:"dst_port,omitempty"`
	Protocol string
}

func (t *traceFlowProtocol) header() *nsx.TransportProtocolHeader {
	h := &nsx.TransportProtocolHeader{}
	switch t.Protocol {
	case protocolTCP:
		h.TcpHeader = &nsx.TcpHeader{SrcPort: &t.SrcPort, DstPort: &t.DstPort}
	case protocolUDP:
		h.UdpHeader = &nsx.UdpHeader{SrcPort: t.SrcPort, DstPort: t.DstPort}
	case protocolICMP:
		h.IcmpEchoRequestHeader = &nsx.IcmpEchoRequestHeader{}
	}
	return h
}

func traceFlowRandomID() (string, error) {
	rnd := make([]byte, traceflowIDSize)
	if _, err := rand.Read(rnd); err != nil {
		return "", err
	}
	return fmt.Sprintf("traceFlow%X", rnd), nil
}

func createTraceFlow(resources *ResourcesContainerModel, server ServerData, srcIP, dstIP string, protocol traceFlowProtocol) (string, error) {
	traceFlowName, err := traceFlowRandomID()
	if err != nil {
		return "", err
	}
	srcVni := resources.GetVirtualNetworkInterfaceByAddress(srcIP)
	dstVni := resources.GetVirtualNetworkInterfaceByAddress(dstIP)

	if srcVni == nil {
		return "", fmt.Errorf("for traceflow, src %s must be a valid vni", srcIP)
	}
	srcMac := srcVni.MacAddress
	dstMac := srcMac
	if dstVni != nil {
		dstMac = dstVni.MacAddress
	}
	if srcVni.LportAttachmentId == nil {
		return "", fmt.Errorf("for traceflow, src %s must have port", srcIP)
	}
	port := resources.GetSegmentPort(*srcVni.LportAttachmentId)
	if port == nil {
		return "", fmt.Errorf("for traceflow, src %s must have port segment", srcIP)
	}

	traceReq := &TraceflowConfig{}
	traceReq.SourceID = port.UniqueId
	traceReq.Packet = &nsx.FieldsPacketData{}
	traceReq.Packet.EthHeader = &nsx.EthernetHeader{SrcMac: srcMac, DstMac: dstMac}
	srcIPv4 := nsx.IPAddress(srcIP)
	dstIPv4 := nsx.IPAddress(dstIP)
	traceReq.Packet.IpHeader = &nsx.Ipv4Header{SrcIp: &srcIPv4, DstIp: &dstIPv4}
	traceReq.Packet.TransportHeader = protocol.header()
	routed := bool(true)
	traceReq.Packet.Routed = &routed

	b, err := json.Marshal(traceReq)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(b, &traceReq)
	if err != nil {
		return "", err
	}
	err = PutResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName), traceReq)
	if err != nil {
		return "", err
	}
	return traceFlowName, nil
}
/////////////////////////////////////////////////////////

func deleteTraceFlow(server ServerData, traceFlowName string) error {
	return DeleteResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName))
}

func collectTraceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	var t TraceFlowObservations
	err := collectResult(server, fmt.Sprintf(getTraceFlowObservationQuery, traceFlowName), &t)
	return t, err
}

func poolTraceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	for i := 0; i < traceflowNumberOfPooling; i++ {
		t, err := collectTraceFlowObservation(server, traceFlowName)
		if err != nil {
			return nil, err
		}
		if t.completed() {
			return t, nil
		}
		time.Sleep(traceflowPoolingTime * time.Second)
	}
	return nil, fmt.Errorf("trace flow is not completed")
}

//////////////////////////////////////////////////////////////////

type traceFlow struct {
	Src         string                `json:"src"`
	Dst         string                `json:"dst"`
	Protocol    traceFlowProtocol     `json:"protocol"`
	Observation TraceFlowObservations `json:"observation"`
	Name        string                `json:"name"`
	Error       string                `json:"error"`
}
type traceFlows []*traceFlow

// ToJSONString converts a traceFlows into a json-formatted-string
func (tfs *traceFlows) toJSONString() (string, error) {
	toPrint, err := json.MarshalIndent(tfs, "", "    ")
	return string(toPrint), err
}

func getTraceFlows(resources *ResourcesContainerModel, server ServerData, ips []string, protocols []traceFlowProtocol) *traceFlows {
	traceFlows := traceFlows{}
	for _, srcIP := range ips {
		for _, dstIP := range ips {
			for _, protocol := range protocols {
				if srcIP == dstIP {
					continue
				}
				traceFlow := &traceFlow{Src: srcIP, Dst: dstIP, Protocol: protocol}
				traceFlows = append(traceFlows, traceFlow)
				if name, err := createTraceFlow(resources, server, srcIP, dstIP, protocol); err != nil {
					logging.Debug(err.Error())
					traceFlow.Error = err.Error()
					} else {
					traceFlow.Name = name
				}
			}
		}
	}
	time.Sleep(traceflowPoolingTime * time.Second)
	for _, traceFlow := range traceFlows {
		if traceFlow.Error != ""{
			continue
		}
		if obs, err := poolTraceFlowObservation(server, traceFlow.Name); err != nil {
			logging.Debug(err.Error())
			traceFlow.Error = err.Error()
		} else {
			traceFlow.Observation = obs
		}
		if err := deleteTraceFlow(server, traceFlow.Name); err != nil {
			logging.Debug(err.Error())
		}
	}
	return &traceFlows
}
func traceFlowsDotGraph(resources *ResourcesContainerModel, ips []string, traceFlows *traceFlows) *common.DotGraph {
	g := common.NewDotGraph(false)
	ipNodes := map[string]*observationNode{}
	for _, ip := range ips {
		ipNodes[ip] = &observationNode{ip: ip}
		vni := resources.GetVirtualNetworkInterfaceByAddress(ip)
		if vni != nil {
			ipNodes[ip].vmName = *resources.GetVirtualMachine(*vni.OwnerVmId).DisplayName
		}
	}
	for _, tf := range *traceFlows {
		observationNodes := tf.Observation.observationNodes(resources)
		lastObs := len(observationNodes) - 1
		g.AddEdge(ipNodes[tf.Src], observationNodes[0], nil)
		g.AddEdge(observationNodes[lastObs], ipNodes[tf.Dst], nil)
		for i := range observationNodes {
			if i != lastObs {
				g.AddEdge(observationNodes[i], observationNodes[i+1], nil)
			}
		}
	}
	return g
}
