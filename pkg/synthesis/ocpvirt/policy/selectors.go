package policy

import (
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	adminv1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/policy_utils"
)

// //////////////////////////////////////////////////////////////////////////////////////////
// policySelector represent a k8s selector. to be later translated to peer, pod selector, etc..
// ite represent one of the following:
// 1. OR of cidrs.
// 2. a label selector of pods
type policySelector struct {
	pods       *metav1.LabelSelector
	cidrs      []string
	namespaces []string
}

func newEmptyPolicySelector() *policySelector {
	return &policySelector{
		pods: &metav1.LabelSelector{},
	}
}

func (selector *policySelector) string() string {
	return fmt.Sprintf("cidrs: %v, namespaes: %v, podsSelector: [%s]",
		selector.cidrs, selector.namespaces, policy_utils.LabelSelectorString(selector.pods))
}

func (selector *policySelector) namespaceLabelSelector(isAdmin bool, policyNamespace string) (selectorRes *metav1.LabelSelector, discard bool) {
	switch {
	case !isAdmin && len(selector.namespaces) == 1 && selector.namespaces[0] == policyNamespace:
		return nil, false // no need for a namespace selector if the peers are in the same namespace of the policy resource
	case len(selector.namespaces) > 0:
		return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: namespaceNameKey, Operator: metav1.LabelSelectorOpIn, Values: selector.namespaces}}}, false
	case isAdmin:
		return &metav1.LabelSelector{}, false
	default:
		return nil, true // todo: should not create rules entry for empty namespaces list..
	}
}

func (selector *policySelector) adminNamespaceLabelSelector() (selectorRes *metav1.LabelSelector) {
	switch {
	case len(selector.namespaces) > 0:
		return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: namespaceNameKey, Operator: metav1.LabelSelectorOpIn, Values: selector.namespaces}}}
	default:
		return &metav1.LabelSelector{}
		//default:
		//	return nil, true // todo: should not create rules entry for empty namespaces list..
	}
}

func (selector *policySelector) isTautology() bool {
	return len(selector.cidrs) == 1 && selector.cidrs[0] == netset.CidrAll
}

func (selector *policySelector) convertAllCidrToAllPodsSelector() {
	selector.cidrs = []string{}
}

func (selector *policySelector) toPolicyPeers(policyNamespace string) []networkingv1.NetworkPolicyPeer {
	if !selector.isTautology() && len(selector.cidrs) > 0 {
		res := make([]networkingv1.NetworkPolicyPeer, len(selector.cidrs))
		for i, cidr := range selector.cidrs {
			res[i] = networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}}
		}
		return res
	}
	nsSelector, discard := selector.namespaceLabelSelector(false, policyNamespace)
	res := []networkingv1.NetworkPolicyPeer{{PodSelector: selector.pods, NamespaceSelector: nsSelector}}
	if selector.isTautology() {
		res = append(res, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: netset.CidrAll}})
	} else if discard {
		return []networkingv1.NetworkPolicyPeer{}
	}
	return res
}

func (selector *policySelector) toPodSelector() metav1.LabelSelector {
	if selector.isTautology() {
		selector.convertAllCidrToAllPodsSelector()
	}
	return *selector.pods
}

func (selector *policySelector) toAdminPolicyIngressPeers() []adminv1alpha1.AdminNetworkPolicyIngressPeer {
	if selector.isTautology() {
		selector.convertAllCidrToAllPodsSelector()
	}
	return []adminv1alpha1.AdminNetworkPolicyIngressPeer{
		{Pods: &adminv1alpha1.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: *selector.adminNamespaceLabelSelector()}}}
}
func (selector *policySelector) toAdminPolicyEgressPeers() []adminv1alpha1.AdminNetworkPolicyEgressPeer {
	if selector.isTautology() {
		return []adminv1alpha1.AdminNetworkPolicyEgressPeer{
			{Networks: []adminv1alpha1.CIDR{adminv1alpha1.CIDR(netset.CidrAll)}},
			{Pods: &adminv1alpha1.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: *selector.adminNamespaceLabelSelector()}}}
	}

	if len(selector.cidrs) > 0 {
		res := make([]adminv1alpha1.AdminNetworkPolicyEgressPeer, len(selector.cidrs))
		for i, cidr := range selector.cidrs {
			res[i] = adminv1alpha1.AdminNetworkPolicyEgressPeer{Networks: []adminv1alpha1.CIDR{adminv1alpha1.CIDR(cidr)}}
		}
		return res
	}
	return []adminv1alpha1.AdminNetworkPolicyEgressPeer{
		{Pods: &adminv1alpha1.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: *selector.adminNamespaceLabelSelector()}}}
}
func (selector *policySelector) toAdminPolicySubject() adminv1alpha1.AdminNetworkPolicySubject {
	if selector.isTautology() {
		selector.convertAllCidrToAllPodsSelector()
	}
	return adminv1alpha1.AdminNetworkPolicySubject{Pods: &adminv1alpha1.NamespacedPod{PodSelector: *selector.pods,
		NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{namespaceNameKey: metav1.NamespaceDefault}}}}
}
