package synthesis

import (
	"slices"

	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
)

func connToPolicyPort(conn *netset.TransportSet) []networking.NetworkPolicyPort {
	ports := &k8sNetworkPorts{}
	connToPorts(ports, conn)
	return ports.ports
}

func connToAdminPolicyPort(conn *netset.TransportSet) []admin.AdminNetworkPolicyPort {
	ports := &k8sAdminNetworkPorts{}
	connToPorts(ports, conn)
	return ports.ports
}

func dnsPorts() []networking.NetworkPolicyPort {
	const dnsPort = 53
	conn := netset.NewTCPorUDPTransport(netp.ProtocolStringUDP, netp.MinPort, netp.MaxPort, dnsPort, dnsPort)
	return connToPolicyPort(conn)
}


// here we have two derived classes: k8sNetworkPorts and k8sAdminNetworkPorts.
// the base class is k8sPorts, which has code that calls methods of the derived classes.
// however, in golang there is no pattern in which the code of the base class can call the derived class methods.
// the solution is:
//  1. the base class is implemented as an interface
//  2. the receiver of the methods of the base class are given to the method as first argument.
//     (connToPorts() gets k8sPorts as the first argument)
type k8sPorts interface {
	// addPorts() adds k8s ports
	addPorts(start, end int64, protocols []core.Protocol)
}

var codeToProtocol = map[int]core.Protocol{netset.UDPCode: core.ProtocolUDP, netset.TCPCode: core.ProtocolTCP}

// convert the connection to ports:
func connToPorts(ports k8sPorts, conn *netset.TransportSet) {
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
		// if we have both TCP and UDP, we also adds SCTP:
		if slices.Contains(protocolsCodes, netset.TCPCode) && slices.Contains(protocolsCodes, netset.UDPCode) {
			protocols = append(protocols, core.ProtocolSCTP)
		}
		for _, portRange := range portRanges.Intervals() {
			ports.addPorts(portRange.Start(), portRange.End(), protocols)
		}
	}
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
			endPort := int32(end)
			endPortPointer = &endPort
		}
	}
	for _, protocol := range protocols {
		ports.ports = append(ports.ports, networking.NetworkPolicyPort{
			Protocol: &protocol,
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
				PortNumber: &(admin.Port{
					Protocol: protocol,
					Port:     int32(start),
				}),
			})
		} else {
			ports.ports = append(ports.ports, admin.AdminNetworkPolicyPort{
				//nolint:gosec // port should fit int32:
				PortRange: &(admin.PortRange{
					Protocol: protocol,
					Start:    int32(start),
					End:      int32(end),
				}),
			})
		}
	}
}
