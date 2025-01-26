package synthesis

import (
	"fmt"

	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

var abstractToAdminRuleAction = map[dfw.RuleAction]admin.AdminNetworkPolicyRuleAction{
	dfw.ActionAllow:     admin.AdminNetworkPolicyRuleActionAllow,
	dfw.ActionDeny:      admin.AdminNetworkPolicyRuleActionDeny,
	dfw.ActionJumpToApp: admin.AdminNetworkPolicyRuleActionPass,
}

type k8sPolicies struct {
	networkPolicies      []*networking.NetworkPolicy
	adminNetworkPolicies []*admin.AdminNetworkPolicy
}

func (policies *k8sPolicies) toNetworkPolicies(model *AbstractModelSyn) ([]*networking.NetworkPolicy, []*admin.AdminNetworkPolicy) {
	for _, p := range model.policy {
		minNumOrRuleInDirection := min(len(p.inbound), len(p.inbound))
		// we assume that an NSX rule is interpreted into two rules - one inbound, and one outbound.
		// so here we segregate the two lists into one
		prioritiesRules := make([]*symbolicRule, 2*minNumOrRuleInDirection)
		isInbound := map[*symbolicRule]bool{}
		for i := 0; i < minNumOrRuleInDirection; i++ {
			prioritiesRules[i*2] = p.inbound[i]
			prioritiesRules[i*2+1] = p.outbound[i]
		}
		prioritiesRules = append(prioritiesRules, p.inbound[minNumOrRuleInDirection:]...)
		prioritiesRules = append(prioritiesRules, p.outbound[minNumOrRuleInDirection:]...)
		for _, rule := range p.inbound {
			isInbound[rule] = true
		}
		for _, rule := range p.outbound {
			isInbound[rule] = false
		}
		for _, rule := range prioritiesRules {
			policies.symbolicRuleToPolicies(model, rule, isInbound[rule])
		}
	}
	return policies.networkPolicies, policies.adminNetworkPolicies
}

func (policies *k8sPolicies) symbolicRuleToPolicies(model *AbstractModelSyn, rule *symbolicRule, inbound bool) {
	isAdmin := model.allowOnlyFromCategory > rule.origRuleCategory
	paths := &rule.allowOnlyRulePaths
	if isAdmin {
		paths = rule.origSymbolicPaths
	}
	for _, p := range *paths {
		if !p.Conn.TCPUDPSet().IsEmpty() {
			policies.addNewPolicy(p, inbound, isAdmin, rule.origRule.Action)
		}
	}
}

func (policies *k8sPolicies) addNewPolicy(p *symbolicexpr.SymbolicPath, inbound, isAdmin bool, action dfw.RuleAction) {
	srcSelector := toSelector(p.Src)
	dstSelector := toSelector(p.Dst)
	if isAdmin {
		ports := connToAdminPolicyPort(p.Conn)
		policies.addAdminNetworkPolicy(srcSelector, dstSelector, ports, inbound,
			abstractToAdminRuleAction[action], fmt.Sprintf("(%s: (%s)", action, p.String()))
	} else {
		ports := connToPolicyPort(p.Conn)
		policies.addNetworkPolicy(srcSelector, dstSelector, ports, inbound, p.String())
	}
}

func (policies *k8sPolicies) addNetworkPolicy(srcSelector, dstSelector *meta.LabelSelector,
	ports []networking.NetworkPolicyPort, inbound bool,
	description string) {
	pol := newNetworkPolicy(fmt.Sprintf("policy_%d", len(policies.networkPolicies)), description)
	policies.networkPolicies = append(policies.networkPolicies, pol)
	if inbound {
		from := []networking.NetworkPolicyPeer{{PodSelector: srcSelector}}
		rules := []networking.NetworkPolicyIngressRule{{From: from, Ports: ports}}
		pol.Spec.Ingress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{"Ingress"}
		pol.Spec.PodSelector = *dstSelector
	} else {
		to := []networking.NetworkPolicyPeer{{PodSelector: dstSelector}}
		rules := []networking.NetworkPolicyEgressRule{{To: to, Ports: ports}}
		pol.Spec.Egress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{"Egress"}
		pol.Spec.PodSelector = *srcSelector
	}
}

func (policies *k8sPolicies) addAdminNetworkPolicy(srcSelector, dstSelector *meta.LabelSelector,
	ports []admin.AdminNetworkPolicyPort, inbound bool, action admin.AdminNetworkPolicyRuleAction, description string) {
	pol := newAdminNetworkPolicy(fmt.Sprintf("admin_policy_%d", len(policies.adminNetworkPolicies)), description)
	policies.adminNetworkPolicies = append(policies.adminNetworkPolicies, pol)
	//nolint:gosec // priority should fit int32:
	pol.Spec.Priority = int32(len(policies.adminNetworkPolicies))
	srcPodsSelector := &admin.NamespacedPod{PodSelector: *srcSelector}
	dstPodsSelector := &admin.NamespacedPod{PodSelector: *dstSelector}
	if inbound {
		from := []admin.AdminNetworkPolicyIngressPeer{{Pods: srcPodsSelector}}
		rules := []admin.AdminNetworkPolicyIngressRule{{From: from, Action: action, Ports: pointerTo(ports)}}
		pol.Spec.Ingress = rules
		pol.Spec.Subject = admin.AdminNetworkPolicySubject{Pods: dstPodsSelector}
	} else {
		to := []admin.AdminNetworkPolicyEgressPeer{{Pods: dstPodsSelector}}
		rules := []admin.AdminNetworkPolicyEgressRule{{To: to, Action: action, Ports: pointerTo(ports)}}
		pol.Spec.Egress = rules
		pol.Spec.Subject = admin.AdminNetworkPolicySubject{Pods: srcPodsSelector}
	}
}

const annotationDescription = "description"

func newNetworkPolicy(name, description string) *networking.NetworkPolicy {
	pol := &networking.NetworkPolicy{}
	pol.TypeMeta.Kind = "NetworkPolicy"
	pol.TypeMeta.APIVersion = "networking.k8s.io/v1"
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{annotationDescription: description}
	return pol
}

func newAdminNetworkPolicy(name, description string) *admin.AdminNetworkPolicy {
	pol := &admin.AdminNetworkPolicy{}
	pol.TypeMeta.Kind = "AdminNetworkPolicy"
	pol.TypeMeta.APIVersion = "policy.networking.k8s.io/v1alpha1"
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{annotationDescription: description}
	return pol
}

////////////////////////////////////////////////////////////////////////////////////////////

func toSelector(con symbolicexpr.Conjunction) *meta.LabelSelector {
	boolToOperator := map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}
	selector := &meta.LabelSelector{}
	for _, a := range con {
		if !a.IsTautology() {
			label, notIn := a.AsSelector()
			req := meta.LabelSelectorRequirement{Key: label, Operator: boolToOperator[notIn]}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		}
	}
	return selector
}
