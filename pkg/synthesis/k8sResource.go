package synthesis

import (
	"fmt"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

type k8sNetworkPolicies struct {
	networkPolicies      []*networking.NetworkPolicy
	adminNetworkPolicies []*admin.AdminNetworkPolicy
}

func newK8sPolicies() *k8sNetworkPolicies {
	return &k8sNetworkPolicies{}
}

func newNetworkPolicy(name, description string) *networking.NetworkPolicy {
	pol := &networking.NetworkPolicy{}
	pol.TypeMeta.Kind = "NetworkPolicy"
	pol.TypeMeta.APIVersion = k8sAPIVersion
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{"description": description}
	return pol
}

func (policies *k8sNetworkPolicies) addNewPolicy(p *symbolicexpr.SymbolicPath, inbound, admin bool, action dfw.RuleAction) {
	srcSelector, dstSelector, ports, empty := toSelectorsAndPorts(p, admin)
	if empty {
		return
	}
	if admin {
		policies.addAdminNetworkPolicy(srcSelector, dstSelector, ports, inbound, action, p.String())
	} else {
		policies.addNetworkPolicy(srcSelector, dstSelector, ports, inbound, p.String())
	}
}

func (policies *k8sNetworkPolicies) addNetworkPolicy(srcSelector, dstSelector *meta.LabelSelector,
	ports k8sPorts, inbound bool,
	description string) {
	pol := newNetworkPolicy(fmt.Sprintf("policy_%d", len(policies.networkPolicies)), description)
	policies.networkPolicies = append(policies.networkPolicies, pol)
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

var abstractToAdminRuleAction = map[dfw.RuleAction]admin.AdminNetworkPolicyRuleAction{
	dfw.ActionAllow:     admin.AdminNetworkPolicyRuleActionAllow,
	dfw.ActionDeny:      admin.AdminNetworkPolicyRuleActionDeny,
	dfw.ActionJumpToApp: admin.AdminNetworkPolicyRuleActionPass,
}

func (policies *k8sNetworkPolicies) addAdminNetworkPolicy(srcSelector, dstSelector *meta.LabelSelector,
	ports k8sPorts, inbound bool, action dfw.RuleAction, description string) {
	pol := newAdminNetworkPolicy(fmt.Sprintf("policy_%d", len(policies.adminNetworkPolicies)), description)
	policies.adminNetworkPolicies = append(policies.adminNetworkPolicies, pol)
	pol.Spec.Priority = int32(999 - len(policies.adminNetworkPolicies))
	if inbound {
		from := []admin.AdminNetworkPolicyIngressPeer{{Namespaces: srcSelector}}
		rules := []admin.AdminNetworkPolicyIngressRule{{From: from, Action: abstractToAdminRuleAction[action], Ports: pointerTo(ports.toNetworkAdminPolicyPort())}}
		pol.Spec.Ingress = rules
		pol.Spec.Subject = admin.AdminNetworkPolicySubject{Namespaces: dstSelector}
	} else {
		to := []admin.AdminNetworkPolicyEgressPeer{{Namespaces: dstSelector}}
		rules := []admin.AdminNetworkPolicyEgressRule{{To: to, Action: abstractToAdminRuleAction[action], Ports: pointerTo(ports.toNetworkAdminPolicyPort())}}
		pol.Spec.Egress = rules
		pol.Spec.Subject = admin.AdminNetworkPolicySubject{Namespaces: srcSelector}
	}
}

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////
type k8sPorts interface {
	toNetworkPolicyPort() []networking.NetworkPolicyPort
	toNetworkAdminPolicyPort() []admin.AdminNetworkPolicyPort
	addPorts(start, end int64, protocols []core.Protocol)
}

func newK8sPorts(admin bool) k8sPorts {
	return &k8sNetworkPorts{}
}

// ////////////////////////////////////////////////////
type k8sNetworkPorts struct {
	ports []networking.NetworkPolicyPort
}

func (ports *k8sNetworkPorts) toNetworkAdminPolicyPort() []admin.AdminNetworkPolicyPort {
	return nil
}
func (ports *k8sNetworkPorts) toNetworkPolicyPort() []networking.NetworkPolicyPort {
	if len(ports.ports) == 0 {
		return nil
	}
	return ports.ports
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

func (ports *k8sAdminNetworkPorts) toNetworkPolicyPort() []networking.NetworkPolicyPort {
	return nil
}
func (ports *k8sAdminNetworkPorts) toNetworkAdminPolicyPort() []admin.AdminNetworkPolicyPort {
	if len(ports.ports) == 0 {
		return nil
	}
	return ports.ports
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
