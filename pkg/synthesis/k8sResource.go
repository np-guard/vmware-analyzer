package synthesis

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type k8sPolicies interface {
	toNetworkPolicies() []*networking.NetworkPolicy
	addNewPolicy(p *symbolicexpr.SymbolicPath, inbound bool)
}
type k8sNetworkPolicies struct {
	policies []*networking.NetworkPolicy
}

func newK8sPolicies(admin bool) k8sPolicies {
	return &k8sNetworkPolicies{}
}

func (policies *k8sNetworkPolicies) toNetworkPolicies() []*networking.NetworkPolicy {
	return policies.policies
}

func newNetworkPolicy(name, description string) *networking.NetworkPolicy {
	pol := &networking.NetworkPolicy{}
	pol.TypeMeta.Kind = "NetworkPolicy"
	pol.TypeMeta.APIVersion = k8sAPIVersion
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{"description": description}
	return pol
}

func (policies *k8sNetworkPolicies) addNewPolicy(p *symbolicexpr.SymbolicPath, inbound bool) {
	srcSelector, dstSelector, ports, empty := toSelectorsAndPorts(p)
	if empty {
		return
	}
	pol := newNetworkPolicy(fmt.Sprintf("policy_%d", len(policies.policies)), p.String())
	policies.policies = append(policies.policies, pol)
	if inbound {
		from := []networking.NetworkPolicyPeer{{PodSelector: srcSelector}}
		rules := []networking.NetworkPolicyIngressRule{{From: from, Ports: ports.toNetworkPolicyPort()}}
		pol.Spec.Ingress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{"Ingress"}
		pol.Spec.PodSelector = *dstSelector
	} else {
		to := []networking.NetworkPolicyPeer{{PodSelector: dstSelector}}
		rules := []networking.NetworkPolicyEgressRule{{To: to, Ports: ports.toNetworkPolicyPort()}}
		pol.Spec.Egress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{"Egress"}
		pol.Spec.PodSelector = *srcSelector
	}
}

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
type k8sPorts interface {
	toNetworkPolicyPort() []networking.NetworkPolicyPort
	addPorts(start, end int64, protocolsCodes []int64)
}

type k8sNetworkPorts struct {
	ports []networking.NetworkPolicyPort
}

func newK8sPorts(admin bool) k8sPorts {
	return &k8sNetworkPorts{}
}

func (ports *k8sNetworkPorts) toNetworkPolicyPort() []networking.NetworkPolicyPort {
	if len(ports.ports) == 0 {
		return nil
	}
	return ports.ports
}

func (ports *k8sNetworkPorts) addPorts(start, end int64, protocolsCodes []int64) {
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
