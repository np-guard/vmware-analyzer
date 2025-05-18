package policy_utils

import (
	"fmt"
	"strings"

	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

const emptySelector = "{}"

func LabelSelectorString(selector *metav1.LabelSelector) string {
	var matchLabelsStr, matchExpressionsStr string
	matchLabelsStr = fmt.Sprintf("%v", selector.MatchLabels)
	matchExpressionsStr = exprRequirementsToString(selector.MatchExpressions)
	switch {
	case len(selector.MatchExpressions) == 0 && len(selector.MatchLabels) == 0:
		return emptySelector

	case len(selector.MatchExpressions) > 0 && len(selector.MatchLabels) == 0:
		return matchExpressionsStr

	case len(selector.MatchExpressions) == 0 && len(selector.MatchLabels) > 0:
		return matchLabelsStr

	default:
		return matchLabelsStr + ";" + matchExpressionsStr
	}
}

func exprRequirementsToString(reqs []metav1.LabelSelectorRequirement) string {
	// function to obtain simplified string from LabelSelectorRequirement.String()
	reqStringFunc := func(r metav1.LabelSelectorRequirement) string {
		const strPrefix = "&LabelSelectorRequirement"
		const existOperator = "Operator:Exists"
		const doesNotExistOperator = "Operator:DoesNotExist"
		const emptyValues = ",Values:[],"
		rStr := strings.ReplaceAll(r.String(), strPrefix, "")
		if strings.Contains(rStr, existOperator) || strings.Contains(rStr, doesNotExistOperator) {
			// no values for these operators
			rStr = strings.ReplaceAll(rStr, emptyValues, "")
		}
		return rStr
	}
	return common.SortedJoinCustomStrFuncSlice(reqs, reqStringFunc, common.CommaSeparator)
}

func AdminPolicySubjectSelectorString(policy *admin.AdminNetworkPolicy) (nsSelecotr, podSelector string) {
	// Exactly one field is set: Subject.Namespaces or Subject.Pods
	if policy.Spec.Subject.Namespaces != nil {
		return LabelSelectorString(policy.Spec.Subject.Namespaces), ""
	}
	return LabelSelectorString(&policy.Spec.Subject.Pods.NamespaceSelector), LabelSelectorString(&policy.Spec.Subject.Pods.PodSelector)
}

type Ntepol interface {
	*networking.NetworkPolicy | *admin.AdminNetworkPolicy
}

func NetpolStr(t *metav1.TypeMeta, o *metav1.ObjectMeta) string {
	return common.JoinNonEmpty([]string{t.Kind, o.Namespace, o.Name}, "/")
}
