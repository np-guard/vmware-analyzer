package collector

import (
	crypto_rand "crypto/rand"
	"encoding/json"
	"fmt"
	"time"
    math_rand "math/rand"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	traceFlowsQuery              = "policy/api/v1/infra/traceflows"
	traceFlowQuery               = "policy/api/v1/infra/traceflows/%s"
	getTraceFlowObservationQuery = "policy/api/v1/infra/traceflows/%s/observations"
)
const (
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolICMP = "icmp"
	TCPFlagSYN   = 2
	maxTraceFlows = 16
)

const (
	traceflowIDSize          = 5
	traceflowPoolingTime     = 3 * time.Second
	traceflowCreationTime    = time.Second
	traceflowNumberOfPooling = 10
)

type traceFlow struct {
	Src          string                `json:"src,omitempty"`
	Dst          string                `json:"dst,omitempty"`
	SrcVM        string                `json:"src_vm,omitempty"`
	DstVM        string                `json:"dst_vm,omitempty"`
	Protocol     TraceFlowProtocol     `json:"protocol,omitempty"`
	Name         string                `json:"name,omitempty"`
	Errors       []string              `json:"errors,omitempty"`
	Results      traceflowResult       `json:"results,omitempty"`
	Observations TraceFlowObservations `json:"observation,omitempty"`
}

type TraceFlowProtocol struct {
	SrcPort  int    `json:"src_port,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

func (t *TraceFlowProtocol) header() *nsx.TransportProtocolHeader {
	h := &nsx.TransportProtocolHeader{}
	switch t.Protocol {
	case ProtocolTCP:
		flags := TCPFlagSYN
		h.TcpHeader = &nsx.TcpHeader{SrcPort: &t.SrcPort, DstPort: &t.DstPort, TcpFlags: &flags}
	case ProtocolUDP:
		h.UdpHeader = &nsx.UdpHeader{SrcPort: t.SrcPort, DstPort: t.DstPort}
	case ProtocolICMP:
		h.IcmpEchoRequestHeader = &nsx.IcmpEchoRequestHeader{}
	}
	return h
}

type TraceFlows []*traceFlow

// ToJSONString converts a traceFlows into a json-formatted-string
func (tfs *TraceFlows) toJSONString() (string, error) {
	toPrint, err := json.MarshalIndent(tfs, "", "    ")
	return string(toPrint), err
}

func GetTraceFlows(resources *ResourcesContainerModel, server ServerData, ips []string, protocols []TraceFlowProtocol) *TraceFlows {
	nPotentialTraceFlows := len(ips)* (len(ips) -1)*len(protocols)
	traceFlows := TraceFlows{}
	for _, srcIP := range ips {
		for _, dstIP := range ips {
			for _, protocol := range protocols {
				if srcIP == dstIP {
					continue
				}
				if nPotentialTraceFlows > maxTraceFlows && math_rand.Intn(nPotentialTraceFlows) > maxTraceFlows{
					continue
				}
				srcVni := resources.GetVirtualNetworkInterfaceByAddress(srcIP)
				dstVni := resources.GetVirtualNetworkInterfaceByAddress(dstIP)
				traceFlow := &traceFlow{Src: srcIP, Dst: dstIP, Protocol: protocol}
				if srcVni != nil {
					traceFlow.SrcVM = *resources.GetVirtualMachine(*srcVni.OwnerVmId).DisplayName
				}
				if dstVni != nil {
					traceFlow.DstVM = *resources.GetVirtualMachine(*dstVni.OwnerVmId).DisplayName
				}

				traceFlows = append(traceFlows, traceFlow)
				if name, err := createTraceFlow(resources, server, srcIP, dstIP, protocol); err != nil {
					logging.Debug(err.Error())
					traceFlow.Errors = append(traceFlow.Errors, err.Error())
				} else {
					traceFlow.Name = name
				}
				time.Sleep(traceflowCreationTime)
			}
		}
	}
	time.Sleep(traceflowPoolingTime)
	for _, traceFlow := range traceFlows {
		if len(traceFlow.Errors) > 0 {
			continue
		}
		if obs, err := poolTraceFlowObservation(server, traceFlow.Name); err != nil {
			logging.Debug(err.Error())
			traceFlow.Errors = append(traceFlow.Errors, err.Error())
		} else {
			traceFlow.Observations = obs
		}
		if err := deleteTraceFlow(server, traceFlow.Name); err != nil {
			logging.Debug(err.Error())
			traceFlow.Errors = append(traceFlow.Errors, err.Error())
		}
		traceFlow.Results = traceFlow.Observations.results()
	}
	return &traceFlows
}

/////////////////////////////////////////////////////////////////////////////////

func traceFlowRandomID() (string, error) {
	rnd := make([]byte, traceflowIDSize)
	if _, err := crypto_rand.Read(rnd); err != nil {
		return "", err
	}
	return fmt.Sprintf("traceFlow%X", rnd), nil
}

func createTraceFlow(resources *ResourcesContainerModel, server ServerData,
	srcIP, dstIP string, protocol TraceFlowProtocol) (string, error) {
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
		time.Sleep(traceflowPoolingTime)
	}
	return nil, fmt.Errorf("trace flow is not completed")
}

//////////////////////////////////////////////////////////////////
