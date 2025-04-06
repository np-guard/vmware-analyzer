package synthesis

import (
	"maps"
	"slices"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type namespace struct {
	name string
}

type namespacesInfo struct {
	namespaces  map[string]*namespace
	vmNamespace map[topology.Endpoint]*namespace
	labelVMs    map[string][]topology.Endpoint
	vms         []topology.Endpoint
}

func newNamespacesInfo(vms []topology.Endpoint) *namespacesInfo {
	return &namespacesInfo{
		namespaces:  map[string]*namespace{},
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
		namespacesInfo.namespaces[namespace.name] = namespace
	}
	if len(namespacesInfo.vms) > len(namespacesInfo.namespaces) {
		defaultNamespace := &namespace{name: meta.NamespaceDefault}
		for _, vm := range namespacesInfo.vms {
			if _, ok := namespacesInfo.vmNamespace[vm]; !ok {
				namespacesInfo.vmNamespace[vm] = defaultNamespace
			}
		}
		namespacesInfo.namespaces[defaultNamespace.name] = defaultNamespace
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
	resource.APIVersion = "v1"
	resource.Name = toLegalK8SString(namespaceInfo.name)
	resource.Namespace = resource.Name
	resource.Labels = map[string]string{}
	return resource
}

func (namespacesInfo *namespacesInfo) getConNamespaces(con symbolicexpr.Conjunction) []*namespace {
	res := []*namespace{}
	for _, a := range con {
		switch {
		case a.IsTautology():
			return slices.Collect(maps.Values(namespacesInfo.namespaces))
		case a.GetExternalBlock() != nil:
			continue
		default:
			label, neg := a.AsSelector()
			vms := namespacesInfo.labelVMs[label]
			if neg {
				vms = slices.DeleteFunc(slices.Clone(namespacesInfo.vms), func(vm topology.Endpoint) bool { return !slices.Contains(vms, vm) })
			}
			for _, vm := range vms {
				res = append(res, namespacesInfo.vmNamespace[vm])
			}
		}
	}
	return common.SliceCompact(res)
}
