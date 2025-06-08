package policy

import (
	"fmt"
	"path"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	adminv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/policy_utils"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

func defaultDenyNetpolDescription(namespace string) string {
	return "default deny policy for namespace " + namespace
}
func defaultDenyNetpolName(namespace string) string {
	return "default-deny-for-" + namespace
}

func (np *PolicyGenerator) addDefaultDenyNetworkPolicy() {
	ruleID := noNSXRuleID
	if np.synthModel.DefaultDenyRule != nil {
		ruleID = np.synthModel.DefaultDenyRule.RuleIDStr()
	}
	for _, namespace := range np.NamespacesInfo.Namespaces {
		policy := newNetworkPolicy(defaultDenyNetpolName(namespace.Name), namespace.Name,
			defaultDenyNetpolDescription(namespace.Name), ruleID, ingressAndEgressType)
		np.NetworkPolicies = append(np.NetworkPolicies, policy)
	}
}

func (np *PolicyGenerator) newPolicy(namespace string, typeValue policyType, description, nsxRuleID string) *networkingv1.NetworkPolicy {
	policyName := fmt.Sprintf("policy-%d", len(np.NetworkPolicies))
	policy := newNetworkPolicy(policyName, namespace, description, nsxRuleID, typeValue)
	np.NetworkPolicies = append(np.NetworkPolicies, policy)
	logging.Debugf("added NetworkPolicy %s", policyName)
	return policy
}

func (np *PolicyGenerator) addNetworkPolicy(srcSelector, dstSelector *policySelector,
	conn *netset.TransportSet, isInbound bool,
	description, nsxRuleID string) {
	ports := connToPolicyPort(conn)
	if isInbound {
		for _, namespace := range dstSelector.namespaces {
			from := srcSelector.toPolicyPeers(namespace)
			if len(from) == 0 { //skip policy generation if no rules are present
				continue
			}
			rules := []networkingv1.NetworkPolicyIngressRule{{From: from, Ports: ports}}
			policy := np.newPolicy(namespace, ingressType, description, nsxRuleID)
			policy.Spec.Ingress = rules
			policy.Spec.PodSelector = dstSelector.toPodSelector()
		}
	} else {
		for _, namespace := range srcSelector.namespaces {
			to := dstSelector.toPolicyPeers(namespace)
			if len(to) == 0 { //skip policy generation if no rules are present
				continue
			}
			rules := []networkingv1.NetworkPolicyEgressRule{{To: to, Ports: ports}}
			policy := np.newPolicy(namespace, egressType, description, nsxRuleID)
			policy.Spec.Egress = rules
			policy.Spec.PodSelector = srcSelector.toPodSelector()
		}
	}
}

func (np *PolicyGenerator) addAdminNetworkPolicy(srcSelector, dstSelector *policySelector,
	conn *netset.TransportSet, inbound bool, action adminv1alpha1.AdminNetworkPolicyRuleAction, description, nsxRuleID string) {
	ports := connToAdminPolicyPort(conn)
	policy := newAdminNetworkPolicy(
		fmt.Sprintf("admin-policy-%d", len(np.AdminNetworkPolicies)),
		description,
		nsxRuleID)
	np.setAdminNetworkPolicy(policy, ports, inbound, action, srcSelector, dstSelector)
}

func dnsPolicyDescription(namespace string) string {
	return "NetworkPolicy to allow access to DNS for namespace " + namespace
}
func dnsPolicyName(namespace string) string {
	return "dns-policy-" + namespace
}

func (np *PolicyGenerator) addDNSAllowNetworkPolicy() {
	for _, namespace := range np.NamespacesInfo.Namespaces {
		policy := newNetworkPolicy(dnsPolicyName(namespace.Name), namespace.Name, dnsPolicyDescription(namespace.Name), noNSXRuleID, egressType)
		np.NetworkPolicies = append(np.NetworkPolicies, policy)
		policy.Spec.PodSelector = metav1.LabelSelector{}
		to := []networkingv1.NetworkPolicyPeer{{
			PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{dnsLabelKey: dnsLabelVal}},
			NamespaceSelector: &metav1.LabelSelector{},
		}}
		policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{To: to, Ports: connToPolicyPort(dnsPortConn)}}
	}
}

func (np *PolicyGenerator) addDNSAllowAdminNetworkPolicy() {
	dnsSelector := newEmptyPolicySelector()
	dnsSelector.pods = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key:      dnsLabelKey,
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{dnsLabelVal}},
	}}
	allSelector := newEmptyPolicySelector()
	ports := connToAdminPolicyPort(dnsPortConn)
	egressPolicy := newAdminNetworkPolicy("egress-dns-policy",
		"Admin Network Policy To Allow Egress Access To DNS Server",
		noNSXRuleID)
	np.setAdminNetworkPolicy(egressPolicy, ports, false, adminv1alpha1.AdminNetworkPolicyRuleActionAllow, allSelector, dnsSelector)
}

func (np *PolicyGenerator) setAdminNetworkPolicy(
	policy *adminv1alpha1.AdminNetworkPolicy, ports []adminv1alpha1.AdminNetworkPolicyPort,
	isInbound bool, action adminv1alpha1.AdminNetworkPolicyRuleAction,
	srcSelector, dstSelector *policySelector) {
	logging.Debug2f("setAdminNetworkPolicy with srcSelector: %s, dstSelector %s  ", srcSelector.string(), dstSelector.string())
	np.AdminNetworkPolicies = append(np.AdminNetworkPolicies, policy)
	//nolint:gosec // priority should fit int32:
	policy.Spec.Priority = int32(len(np.AdminNetworkPolicies))
	if isInbound {
		from := srcSelector.toAdminPolicyIngressPeers()
		rules := []adminv1alpha1.AdminNetworkPolicyIngressRule{{From: from, Action: action, Ports: &ports}}
		policy.Spec.Ingress = rules
		policy.Spec.Subject = dstSelector.toAdminPolicySubject()
	} else {
		to := dstSelector.toAdminPolicyEgressPeers()
		rules := []adminv1alpha1.AdminNetworkPolicyEgressRule{{To: to, Action: action, Ports: &ports}}
		policy.Spec.Egress = rules
		policy.Spec.Subject = srcSelector.toAdminPolicySubject()
	}
	ns, pods := policy_utils.AdminPolicySubjectSelectorString(policy)
	logging.Debug2f("res admin subjet ns selector: %s", ns)
	logging.Debug2f("res admin subjet pod selector: %s", pods)
}

var abstractToAdminRuleAction = map[dfw.RuleAction]adminv1alpha1.AdminNetworkPolicyRuleAction{
	dfw.ActionAllow:     adminv1alpha1.AdminNetworkPolicyRuleActionAllow,
	dfw.ActionDeny:      adminv1alpha1.AdminNetworkPolicyRuleActionDeny,
	dfw.ActionJumpToApp: adminv1alpha1.AdminNetworkPolicyRuleActionPass,
}

const dnsPort = 53
const dnsLabelKey = "k8s-app"
const dnsLabelVal = "kube-dns"
const noNSXRuleID = "none"

var namespaceNameKey = path.Join("kubernetes.io", metav1.ObjectNameField)

func newNetworkPolicy(name, namespace, description, nsxRuleID string, typeValue policyType) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{}
	policy.Kind = "NetworkPolicy"
	policy.APIVersion = "networking.k8s.io/v1"
	policy.Name = utils.ToLegalK8SString(name)
	policy.Namespace = namespace
	policy.Annotations = map[string]string{
		policy_utils.AnnotationDescription: description,
		policy_utils.AnnotationNSXRuleUID:  nsxRuleID,
	}
	policy.Spec = networkingv1.NetworkPolicySpec{
		PolicyTypes: typeValue.get(),
	}
	return policy
}

func newAdminNetworkPolicy(name, description, nsxRuleID string) *adminv1alpha1.AdminNetworkPolicy {
	policy := &adminv1alpha1.AdminNetworkPolicy{}
	policy.Kind = "AdminNetworkPolicy"
	policy.APIVersion = "policy.networking.k8s.io/v1alpha1"
	policy.Name = utils.ToLegalK8SString(name)
	policy.Annotations = map[string]string{
		policy_utils.AnnotationDescription: description,
		policy_utils.AnnotationNSXRuleUID:  nsxRuleID,
	}
	return policy
}

type policyType int

const (
	ingressType policyType = iota
	egressType
	ingressAndEgressType
)

func (p policyType) get() []networkingv1.PolicyType {
	switch p {
	case ingressType:
		return []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	case egressType:
		return []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
	case ingressAndEgressType:
		return []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}
	}
	return []networkingv1.PolicyType{}
}

func (p policyType) string() string {
	return common.JoinCustomStrFuncSlice(p.get(), func(p networkingv1.PolicyType) string { return string(p) }, ",")
}

func directionStr(isIngress bool) string {
	if isIngress {
		return ingressType.string()
	}
	return egressType.string()
}
