package topology

import (
	"fmt"
	"slices"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	udnv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

// Namespace captures info to generate namespace and udn resources
type Namespace struct {
	Name           string
	origNSXSegment *topology.Segment
}

func (n *Namespace) createNamespace() *core.Namespace {
	resource := &core.Namespace{}
	resource.Kind = "Namespace"
	resource.APIVersion = apiVersion
	resource.Name = n.Name
	// todo: add labels to namespaces (e.g. based on segment tags)
	resource.Labels = map[string]string{
		"kubernetes.io/metadata.name":              resource.Name, // name label is added to all namespaces
		"k8s.ovn.org/primary-user-defined-network": "",            // udn label to enable network segmentation per namespace as primary udn
	}
	return resource
}

func (n *Namespace) String() string {
	return n.Name
}

func (n *Namespace) getSegmentCIDR() (string, error) {
	if n.origNSXSegment != nil {
		ipblock := n.origNSXSegment.Block
		cidrs := ipblock.ToCidrList()
		if len(cidrs) == 1 {
			return cidrs[0], nil
		}
	}
	return "", fmt.Errorf("could not get cidr from nsx segment")
}

func (n *Namespace) createNamespacePrimaryUDN() *udnv1.UserDefinedNetwork {
	cidr, err := n.getSegmentCIDR()
	if err != nil {
		logging.Debugf("failed to generate udn of namespace %s: %s", n.Name, err.Error())
		return nil
	}
	namespace := n.Name
	name := "udn-" + n.Name // TODO: revisit name per udn and namespace generation
	return createUDNResource(name, namespace, cidr)
}

//////////////////////////////////////////////////////////////////////////////////

// NamespacesInfo captures info to generate namespaces
type NamespacesInfo struct {
	// input objects
	vms      []topology.Endpoint            // list of all vms
	labelVMs map[string][]topology.Endpoint // map from label key to its list of vms

	// internal caching
	cacheConjNamespaces map[string][]string // cache conj namespaces computed by GetConjunctionNamespaces()

	// the namespaces to generate
	Namespaces  []*Namespace                     // list all namespaces to generate
	vmNamespace map[topology.Endpoint]*Namespace // map from vm to its namespace-to-generate
}

func newNamespacesInfo(synthModel *model.AbstractModelSyn) *NamespacesInfo {
	res := &NamespacesInfo{
		vms:                 synthModel.VMs,
		labelVMs:            synthModel.LabelsToVMsMap,
		vmNamespace:         map[topology.Endpoint]*Namespace{},
		cacheConjNamespaces: map[string][]string{},
	}
	res.initNamespaces(synthModel)
	return res
}

func (ni *NamespacesInfo) initNamespaces(synthModel *model.AbstractModelSyn) {
	// create the namespaces:
	for _, segment := range synthModel.Segments {
		// current convention: namespace name is equal to NSX segment name
		namespace := &Namespace{
			Name:           utils.ToLegalK8SString(segment.Name),
			origNSXSegment: segment,
		}
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

func (ni *NamespacesInfo) createNamespaces() (res []*core.Namespace) {
	for _, namespace := range ni.Namespaces {
		if namespace.Name != meta.NamespaceDefault {
			res = append(res, namespace.createNamespace())
		}
	}
	return res
}

func (ni *NamespacesInfo) createUDNs() (res []*udnv1.UserDefinedNetwork) {
	for _, namespace := range ni.Namespaces {
		if namespace.Name != meta.NamespaceDefault {
			if udn := namespace.createNamespacePrimaryUDN(); udn != nil {
				res = append(res, udn)
			}
		}
	}
	return res
}

const apiVersion = "v1" // for both pods and namespaces

// GetConjunctionNamespaces() returns the namspaces of a Term
// since the Term is abstract, we:
// 1. obtain the list of VMs using the atom labels
// 2. find the namespaces of the VMs
func (ni *NamespacesInfo) GetConjunctionNamespaces(conj symbolicexpr.Term) []string {
	if cachedRes, ok := ni.cacheConjNamespaces[conj.String()]; ok {
		return cachedRes
	}

	conjVMs := slices.Clone(ni.vms)
	res := []*Namespace{}
	for _, atom := range conj {
		switch {
		case atom.IsTautology(), atom.IsAllGroups():
			resStr := common.StringifiedSliceToStrings(ni.Namespaces)
			ni.cacheConjNamespaces[conj.String()] = resStr
			return resStr
		case atom.IsAllExternal(), atom.GetExternalBlock() != nil:
			continue
		default:
			label, neg := atom.AsSelector()
			vms := ni.labelVMs[label]
			if neg {
				vms = slices.DeleteFunc(slices.Clone(ni.vms), func(vm topology.Endpoint) bool { return slices.Contains(vms, vm) })
			}
			// TODO: consider changing the logic here
			conjVMs = topology.Intersection(conjVMs, vms)
			if len(conjVMs) == 0 {
				break
			}
			//nolint: gocritic // keep  commented-out code for now
			/*for _, vm := range vms {
				res = append(res, ni.vmNamespace[vm])
			}*/
		}
	}
	for _, vm := range conjVMs {
		res = append(res, ni.vmNamespace[vm])
	}
	res = common.SliceCompact(res)
	// sort it by order of the namespacesInfo.namespaces
	slices.SortFunc(res, func(n1, n2 *Namespace) int {
		return slices.Index(ni.Namespaces, n1) - slices.Index(ni.Namespaces, n2)
	})
	resStr := common.StringifiedSliceToStrings(res)
	logging.Debug2f("input Term: %s, result namespaces: %v", conj.String(), resStr)
	ni.cacheConjNamespaces[conj.String()] = resStr
	return resStr
}
