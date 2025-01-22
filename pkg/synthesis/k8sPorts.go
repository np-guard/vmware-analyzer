package synthesis

import (
	"slices"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)


type k8sPorts interface {
	addPorts(start, end int64, protocols []core.Protocol)
}

var codeToProtocol = map[int]core.Protocol{netset.UDPCode: core.ProtocolUDP, netset.TCPCode: core.ProtocolTCP}

func toPolicyPorts(ports k8sPorts, conn *netset.TransportSet, admin bool) {
	tcpUDPSet := conn.TCPUDPSet()
	if tcpUDPSet.IsAll() {
		return
	}
	partitions := tcpUDPSet.Partitions()
	for _, partition := range partitions {
		protocolsCodes := partition.S1.Elements()
		portRanges := partition.S3
		protocols := []core.Protocol{}
		for _, protocolCode := range protocolsCodes {
			protocols = append(protocols, codeToProtocol[int(protocolCode)])
		}
		if slices.Contains(protocolsCodes, netset.TCPCode) && slices.Contains(protocolsCodes, netset.UDPCode) {
			protocols = append(protocols, core.ProtocolSCTP)
		}
		for _, portRange := range portRanges.Intervals() {
			ports.addPorts(portRange.Start(), portRange.End(), protocols)
		}
	}
}

func pointerTo[T any](t T) *T {
	return &t
}

// ////////////////////////////////////////////////////
type k8sNetworkPorts struct {
	ports []networking.NetworkPolicyPort
}

func (ports *k8sNetworkPorts) addPorts(start, end int64, protocols []core.Protocol) {
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
	for _, protocol := range protocols {
		ports.ports = append(ports.ports, networking.NetworkPolicyPort{
			Protocol: pointerTo(protocol),
			Port:     portPointer,
			EndPort:  endPortPointer})
	}
}

// ///////////////////////////////////////////////////////////////////////////////////////////
type k8sAdminNetworkPorts struct {
	ports []admin.AdminNetworkPolicyPort
}

func (ports *k8sAdminNetworkPorts) addPorts(start, end int64, protocols []core.Protocol) {
	for _, protocol := range protocols {
		if end == start {
			//nolint:gosec // port should fit int32:
			ports.ports = append(ports.ports, admin.AdminNetworkPolicyPort{
				PortNumber: pointerTo(admin.Port{
					Protocol: protocol,
					Port:     int32(start),
				}),
			})
		} else {
			ports.ports = append(ports.ports, admin.AdminNetworkPolicyPort{
				PortRange: pointerTo(admin.PortRange{
					Protocol: protocol,
					Start:    int32(start),
					End:      int32(end),
				}),
			})

		}
	}
}
