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

func (n *Namespace) createResource() *core.Namespace {
	resource := &core.Namespace{}
	resource.Kind = "Namespace"
	resource.APIVersion = apiVersion
	resource.Name = utils.ToLegalK8SString(n.Name)
	resource.Namespace = resource.Name
	resource.Labels = map[string]string{}
	return resource
}

//////////////////////////////////////////////////////////////////////////////////

type NamespacesInfo struct {
	// input objects
	vmNamespace map[topology.Endpoint]*Namespace
	vms         []topology.Endpoint
	labelVMs    map[string][]topology.Endpoint

	// the namespaces to generate
	Namespaces []*Namespace
}

func NewNamespacesInfo(vms []topology.Endpoint) *NamespacesInfo {
	return &NamespacesInfo{
		vms:         vms,
		vmNamespace: map[topology.Endpoint]*Namespace{},
		labelVMs:    map[string][]topology.Endpoint{},
	}
}

func (ni *NamespacesInfo) InitNamespaces(synthModel *model.AbstractModelSyn) {
	ni.labelVMs = utils.CollectLabelsVMs(synthModel)

	// create the namespaces:
	for _, segment := range synthModel.Segments {
		namespace := &Namespace{Name: segment.Name}
		for _, vm := range segment.VMs {
			ni.vmNamespace[vm] = namespace
		}
		ni.Namespaces = append(ni.Namespaces, namespace)
	}
	// for VMs w/o segments - add the default namespace
	if len(ni.vms) == 0 || len(ni.vms) > len(ni.vmNamespace) {
		defaultNamespace := &Namespace{Name: meta.NamespaceDefault}
		for _, vm := range ni.vms {
			if _, ok := ni.vmNamespace[vm]; !ok {
				ni.vmNamespace[vm] = defaultNamespace
			}
		}
		ni.Namespaces = append(ni.Namespaces, defaultNamespace)
	}
}

func (ni *NamespacesInfo) CreateNamespaces() []*core.Namespace {
	res := []*core.Namespace{}
	for _, namespace := range ni.Namespaces {
		if namespace.Name != meta.NamespaceDefault {
			res = append(res, namespace.createResource())
		}
	}
	return res
}

const apiVersion = "v1"

// getConjunctionNamespaces() obtain the namspaces of a Conjunction
// since the Conjunction is abstract, we:
// 1. obtain the list of VMs using the atom labels
// 2. find the namespaces of the VM
func (ni *NamespacesInfo) GetConjunctionNamespaces(con symbolicexpr.Conjunction) []*Namespace {
	res := []*Namespace{}
	for _, a := range con {
		switch {
		case a.IsTautology(), a.IsAllGroups():
			return ni.Namespaces
		case a.IsAllExternal(), a.GetExternalBlock() != nil:
			continue
		default:
			label, neg := a.AsSelector()
			vms := ni.labelVMs[label]
			if neg {
				vms = slices.DeleteFunc(slices.Clone(ni.vms), func(vm topology.Endpoint) bool { return slices.Contains(vms, vm) })
			}
			for _, vm := range vms {
				res = append(res, ni.vmNamespace[vm])
			}
		}
	}
	res = common.SliceCompact(res)
	// sort it by order of the namespacesInfo.namespaces
	slices.SortFunc(res, func(n1, n2 *Namespace) int {
		return slices.Index(ni.Namespaces, n1) - slices.Index(ni.Namespaces, n2)
	})
	return res
}
