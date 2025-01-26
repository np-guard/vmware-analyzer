package synthesis

import (
	"path"

	core "k8s.io/api/core/v1"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

func createK8sResources(model *AbstractModelSyn, outDir string) error {
	k8sPolicies := &k8sPolicies{}
	policies, adminPolicies := k8sPolicies.toNetworkPolicies(model)
	if len(policies) > 0 {
		policiesFileName := path.Join(outDir, "policies.yaml")
		if err := common.WriteYamlUsingJSON(policies, policiesFileName); err != nil {
			return err
		}
	}
	if len(adminPolicies) > 0 {
		adminPoliciesFileName := path.Join(outDir, "adminPolicies.yaml")
		if err := common.WriteYamlUsingJSON(adminPolicies, adminPoliciesFileName); err != nil {
			return err
		}
	}
	pods := toPods(model)
	podsFileName := path.Join(outDir, "pods.yaml")
	if err := common.WriteYamlUsingJSON(pods, podsFileName); err != nil {
		return err
	}
	logging.Debugf("%d k8s network policies, and %d admin network policies were generated at %s",
		len(policies), len(adminPolicies), outDir)
	for _, format := range []string{"txt", "dot"} {
		out, err := k8sAnalyzer(outDir, format)
		if err != nil {
			return err
		}
		err = common.WriteToFile(path.Join(outDir, "k8s_connectivity."+format), out)
		if err != nil {
			return err
		}
	}
	return nil
}

// ///////////////////////////////////////////////////////////////////////////////
func toPods(model *AbstractModelSyn) []*core.Pod {
	pods := []*core.Pod{}
	for _, vm := range model.vms {
		pod := &core.Pod{}
		pod.TypeMeta.Kind = "Pod"
		pod.TypeMeta.APIVersion = "v1"
		pod.ObjectMeta.Name = vm.Name()
		if len(model.epToGroups[vm]) == 0 {
			continue
		}
		pod.ObjectMeta.Labels = map[string]string{}
		for _, group := range model.epToGroups[vm] {
			label, _ := symbolicexpr.NewAtomicTerm(group, group.Name(), false).AsSelector()
			pod.ObjectMeta.Labels[label] = "true"
		}
		pods = append(pods, pod)
	}
	return pods
}

///////////////////////////////////////////////////////////////////////////

func k8sAnalyzer(outDir, format string) (string, error) {
	analyzer := connlist.NewConnlistAnalyzer(connlist.WithOutputFormat(format))

	conns, _, err := analyzer.ConnlistFromDirPath(outDir)
	if err != nil {
		return "", err
	}
	return analyzer.ConnectionsListToString(conns)
}
