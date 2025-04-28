package topology

import (
	"slices"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

type Namespace struct {
	Name string
}

type NamespacesInfo struct {
	Namespaces  []*Namespace
	VMNamespace map[topology.Endpoint]*Namespace
	labelVMs    map[string][]topology.Endpoint
	vms         []topology.Endpoint
}

func NewNamespacesInfo(vms []topology.Endpoint) *NamespacesInfo {
	return &NamespacesInfo{
		VMNamespace: map[topology.Endpoint]*Namespace{},
		vms:         vms,
	}
}

func (namespacesInfo *NamespacesInfo) InitNamespaces(synthModel *model.AbstractModelSyn) {
	namespacesInfo.labelVMs = utils.CollectLabelsVMs(synthModel)
	// create the namespaces:
	for _, segment := range synthModel.Segments {
		namespace := &Namespace{Name: segment.Name}
		for _, vm := range segment.VMs {
			namespacesInfo.VMNamespace[vm] = namespace
		}
		namespacesInfo.Namespaces = append(namespacesInfo.Namespaces, namespace)
	}
	// for VMs w/o segments - add the default namespace
	if len(namespacesInfo.vms) == 0 || len(namespacesInfo.vms) > len(namespacesInfo.VMNamespace) {
		defaultNamespace := &Namespace{Name: meta.NamespaceDefault}
		for _, vm := range namespacesInfo.vms {
			if _, ok := namespacesInfo.VMNamespace[vm]; !ok {
				namespacesInfo.VMNamespace[vm] = defaultNamespace
			}
		}
		namespacesInfo.Namespaces = append(namespacesInfo.Namespaces, defaultNamespace)
	}
}

func (namespacesInfo *NamespacesInfo) CreateResources() []*core.Namespace {
	res := []*core.Namespace{}
	for _, namespace := range namespacesInfo.Namespaces {
		if namespace.Name != meta.NamespaceDefault {
			res = append(res, namespace.createResource())
		}
	}
	return res
}

func (namespaceInfo *Namespace) createResource() *core.Namespace {
	resource := &core.Namespace{}
	resource.Kind = "Namespace"
	resource.APIVersion = "v1"
	resource.Name = utils.ToLegalK8SString(namespaceInfo.Name)
	resource.Namespace = resource.Name
	resource.Labels = map[string]string{}
	return resource
}

// getConjunctionNamespaces() obtain the namspaces of a Conjunction
// since the Conjunction is abstract, we:
// 1. obtain the list of VMs using the atom labels
// 2. find the namespaces of the VM
func (namespacesInfo *NamespacesInfo) GetConjunctionNamespaces(con symbolicexpr.Conjunction) []*Namespace {
	res := []*Namespace{}
	for _, a := range con {
		switch {
		case a.IsTautology(), a.IsAllGroups():
			return namespacesInfo.Namespaces
		case a.IsAllExternal(), a.GetExternalBlock() != nil:
			continue
		default:
			label, neg := a.AsSelector()
			vms := namespacesInfo.labelVMs[label]
			if neg {
				vms = slices.DeleteFunc(slices.Clone(namespacesInfo.vms), func(vm topology.Endpoint) bool { return slices.Contains(vms, vm) })
			}
			for _, vm := range vms {
				res = append(res, namespacesInfo.VMNamespace[vm])
			}
		}
	}
	res = common.SliceCompact(res)
	// sort it by order of the namespacesInfo.namespaces
	slices.SortFunc(res, func(n1, n2 *Namespace) int {
		return slices.Index(namespacesInfo.Namespaces, n1) - slices.Index(namespacesInfo.Namespaces, n2)
	})
	return res
}
