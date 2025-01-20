package synthesis

import (
	"slices"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type networkPolicy interface {
}

type k8sPorts interface {
	toNetworkPolicyPort() []networking.NetworkPolicyPort
	addPorts(start, end int64, protocolsCodes []int64)
}

type k8sNetworkPorts struct {
	ports []networking.NetworkPolicyPort
}

func newK8sPorts(admin bool) k8sPorts {
	return k8sNetworkPorts{}
}

func (ports k8sNetworkPorts) toNetworkPolicyPort() []networking.NetworkPolicyPort {
	if len(ports.ports) == 0 {
		return nil
	}
	return ports.ports
}

func (ports k8sNetworkPorts) addPorts(start, end int64, protocolsCodes []int64) {
	var portPointer *intstr.IntOrString
	var endPortPointer *int32
	if start != netp.MinPort || end != netp.MaxPort {
		port := intstr.FromInt(int(start))
		portPointer = &port
		if end != start {
			//nolint:gosec // port should fit int32:
			endPort := int32(end)
			endPortPointer = &endPort
		}
	}
	for _, protocolCode := range protocolsCodes {
		ports.ports = append(ports.ports, networking.NetworkPolicyPort{
			Protocol: pointerTo(codeToProtocol[int(protocolCode)]),
			Port:     portPointer,
			EndPort:  endPortPointer})
	}
	if slices.Contains(protocolsCodes, netset.TCPCode) && slices.Contains(protocolsCodes, netset.UDPCode) {
		ports.ports = append(ports.ports, networking.NetworkPolicyPort{Protocol: pointerTo(core.ProtocolSCTP), Port: portPointer, EndPort: endPortPointer})
	}

}
