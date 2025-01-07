package synthesis

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NSXToAbstractModelSynthesis(recourses *collector.ResourcesContainerModel) (*symbolicPolicy, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	fmt.Println(stringCategoryToSymbolicPolicy(config.Fw.CategoriesSpecs, categoryToPolicy))
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, categoryToPolicy)
	readPolicy(&allowOnlyPolicy)
	return &allowOnlyPolicy, nil
}

func readPolicy(p *symbolicPolicy) {
	policies := []*networking.NetworkPolicy{}
	newPolicy := func() *networking.NetworkPolicy {
		pol := &networking.NetworkPolicy{}
		pol.TypeMeta.Kind = "NetworkPolicy"
		pol.TypeMeta.APIVersion = "networking.k8s.io/v1"
		pol.ObjectMeta.Name = fmt.Sprintf("policy_%d", len(policies))
		policies = append(policies, pol)
		return pol
	}
	for _, ib := range p.outbound {
		for _, p := range ib.allowOnlyRulePaths {
			srcSelector := conjunctionToSelector(&p.Src)
			dstSelector := conjunctionToSelector(&p.Dst)
			to := []networking.NetworkPolicyPeer{{PodSelector: dstSelector}}
			rules := []networking.NetworkPolicyEgressRule{{To: to}}
			pol := newPolicy()
			pol.Spec.Egress = rules
			pol.Spec.PolicyTypes = []networking.PolicyType{"Egress"}
			pol.Spec.PodSelector = *srcSelector

		}
	}
}

func conjunctionToSelector(con *symbolicexpr.Conjunction) *meta.LabelSelector {
	selector := &meta.LabelSelector{}
	for _, a := range *con {
		key, notIn, vals := a.AsSelector()
		switch {
		case len(vals) == 0: // tautology
		case !notIn && len(vals) == 1:
			selector.MatchLabels = map[string]string{key: vals[0]}
		case !notIn:
			req := meta.LabelSelectorRequirement{Key: key, Operator: meta.LabelSelectorOpIn, Values: vals}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		case notIn:
			req := meta.LabelSelectorRequirement{Key: key, Operator: meta.LabelSelectorOpNotIn, Values: vals}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		}
	}
	return selector
}
