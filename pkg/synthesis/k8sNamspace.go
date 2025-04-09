package synthesis

import (
	"slices"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
)

type namespace struct {
	name string
}

type namespacesInfo struct {
	namespaces  []*namespace
	vmNamespace map[topology.Endpoint]*namespace
	labelVMs    map[string][]topology.Endpoint
	vms         []topology.Endpoint
}

func newNamespacesInfo(vms []topology.Endpoint) *namespacesInfo {
	return &namespacesInfo{
		vmNamespace: map[topology.Endpoint]*namespace{},
		vms:         vms,
	}
}

func (namespacesInfo *namespacesInfo) initNamespaces(model *AbstractModelSyn) {
	namespacesInfo.labelVMs = collectLabelsVMs(model)
	// create the namespaces:
	for _, segment := range model.segments {
		namespace := &namespace{name: segment.Name}
		for _, vm := range segment.VMs {
			namespacesInfo.vmNamespace[vm] = namespace
		}
		namespacesInfo.namespaces = append(namespacesInfo.namespaces, namespace)
	}
	// for VMs w/o segments - add the default namespace
	if len(namespacesInfo.vms) == 0 || len(namespacesInfo.vms) > len(namespacesInfo.vmNamespace) {
		defaultNamespace := &namespace{name: meta.NamespaceDefault}
		for _, vm := range namespacesInfo.vms {
			if _, ok := namespacesInfo.vmNamespace[vm]; !ok {
				namespacesInfo.vmNamespace[vm] = defaultNamespace
			}
		}
		namespacesInfo.namespaces = append(namespacesInfo.namespaces, defaultNamespace)
	}
}

func (namespacesInfo *namespacesInfo) createResources() []*core.Namespace {
	res := []*core.Namespace{}
	for _, namespace := range namespacesInfo.namespaces {
		if namespace.name != meta.NamespaceDefault {
			res = append(res, namespace.createResource())
		}
	}
	return res
}

func (namespaceInfo *namespace) createResource() *core.Namespace {
	resource := &core.Namespace{}
	resource.Kind = "Namespace"
	resource.APIVersion = apiVersion
	resource.Name = toLegalK8SString(namespaceInfo.name)
	resource.Namespace = resource.Name
	resource.Labels = map[string]string{}
	return resource
}

// getConjunctionNamespaces() obtain the namspaces of a Conjunction
// since the Conjunction is abstract, we:
// 1. obtain the list of VMs using the atom labels
// 2. find the namespaces of the VM
func (namespacesInfo *namespacesInfo) getConjunctionNamespaces(con symbolicexpr.Conjunction) []*namespace {
	res := []*namespace{}
	for _, a := range con {
		switch {
		case a.IsTautology(), a.IsAllGroups():
			return namespacesInfo.namespaces
		case a.IsAllExternal(), a.GetExternalBlock() != nil:
			continue
		default:
			label, neg := a.AsSelector()
			vms := namespacesInfo.labelVMs[label]
			if neg {
				vms = slices.DeleteFunc(slices.Clone(namespacesInfo.vms), func(vm topology.Endpoint) bool { return slices.Contains(vms, vm) })
			}
			for _, vm := range vms {
				res = append(res, namespacesInfo.vmNamespace[vm])
			}
		}
	}
	res = common.SliceCompact(res)
	// sort it by order of the namespacesInfo.namespaces
	slices.SortFunc(res, func(n1, n2 *namespace) int {
		return slices.Index(namespacesInfo.namespaces, n1) - slices.Index(namespacesInfo.namespaces, n2)
	})
	return res
}
