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
	srcPort, dstPort int
	protocol         string
}

func (t *traceFlowProtocol) header() *nsx.TransportProtocolHeader {
	h := &nsx.TransportProtocolHeader{}
	switch t.protocol {
	case protocolTCP:
		h.TcpHeader = &nsx.TcpHeader{SrcPort: &t.srcPort, DstPort: &t.dstPort}
	case protocolUDP:
		h.UdpHeader = &nsx.UdpHeader{SrcPort: t.srcPort, DstPort: t.dstPort}
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

func traceFlow(resources *ResourcesContainerModel, server ServerData, srcIP, dstIP string, protocol traceFlowProtocol) (string, error) {
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

type traceFlowKey struct {
	src, dst string
}
type traceFlows map[traceFlowKey]TraceFlowObservations

func getTraceFlows(resources *ResourcesContainerModel, server ServerData, ips []string, protocol traceFlowProtocol) *traceFlows {
	tfNames := map[traceFlowKey]string{}
	for _, srcIP := range ips {
		for _, dstIP := range ips {
			key := traceFlowKey{srcIP, dstIP}
			if srcIP == dstIP {
				continue
			}
			if name, err := traceFlow(resources, server, srcIP, dstIP, protocol); err != nil {
				logging.Debug(err.Error())
			} else {
				tfNames[key] = name
			}
		}
	}
	traceFlows := traceFlows{}
	for key, name := range tfNames {
		if obs, err := poolTraceFlowObservation(server, name); err != nil {
			logging.Debug(err.Error())
		} else {
			traceFlows[key] = obs
		}
		if err := deleteTraceFlow(server, name); err != nil {
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
	for key, tf := range *traceFlows {
		observationNodes := tf.observationNodes(resources)
		lastObs := len(observationNodes) - 1
		g.AddEdge(ipNodes[key.src], observationNodes[0], nil)
		g.AddEdge(observationNodes[lastObs], ipNodes[key.dst], nil)
		for i := range observationNodes {
			if i != lastObs {
				g.AddEdge(observationNodes[i], observationNodes[i+1], nil)
			}
		}
	}
	return g
}
