package topology

import (
	"slices"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

func (ni *NamespacesInfo) symbolicAtomToNamespaces(atom symbolicexpr.Atomic) []*Namespace {
	if atom.IsTautology() || atom.IsAllGroups() {
		return ni.Namespaces // all namespaces
	}

	label, neg := atom.AsSelector()
	vms := ni.labelVMs[label]
	if neg {
		vms = slices.DeleteFunc(slices.Clone(ni.vms), func(vm topology.Endpoint) bool { return slices.Contains(vms, vm) })
	}

	// if there are vms associated with the atom's selector expression, focus on these namespaces only in policy generation
	if len(vms) > 0 {
		return ni.vmsNamespaces(vms)
	}
	// else, consider all namespaces
	return ni.Namespaces
}

// list namespaces sets for each atom in conj
func (ni *NamespacesInfo) conjNamespacesPerAtom(conj symbolicexpr.Term) [][]*Namespace {
	nslists := [][]*Namespace{} // list namespaces sets for each atom in conj
	for _, atom := range conj {
		if atom.IsAllExternal() || atom.GetExternalBlock() != nil {
			continue
		}
		nslists = append(nslists, ni.symbolicAtomToNamespaces(atom))
	}
	return nslists
}

// conjNamespaces returns the list of relevant namespaces from a conjunction expression, to policy generation.
// it possibly applies optimization to namespaces inferred as relevant, to avoid generating multiple policies for irrelevant namespaces.
// this depends on the options.PolicyOptimizationLevel value.
func (ni *NamespacesInfo) conjNamespaces(conj symbolicexpr.Term) []*Namespace {
	// TODO: check the logic below
	// assuming can use the current optimization for now:
	// if there are common namespaces to all atoms in term - use only them for policy generation
	// if the intersection is empty, consider this as disjoint groups intersection

	switch ni.options.PolicyOptimizationLevel {
	case common.PolicyOptimizationLevelNone:
		return ni.Namespaces // always consider all namespaces for any conj expression

	case common.PolicyOptimizationLevelModerate:
		return nsUnion(ni.conjNamespacesPerAtom(conj))

	case common.PolicyOptimizationLevelMax:
		return ni.nsIntersection(ni.conjNamespacesPerAtom(conj))

	default:
		return nil // should not get here...
	}
}

func nsUnion(nslists [][]*Namespace) []*Namespace {
	res := []*Namespace{}
	for _, nslist := range nslists {
		res = append(res, nslist...)
	}
	return common.SliceCompact(res)
}
func (ni *NamespacesInfo) nsIntersection(nslists [][]*Namespace) []*Namespace {
	nsMap := map[*Namespace]int{}
	for _, ns := range ni.Namespaces {
		nsMap[ns] = 0
	}

	for _, nslist := range nslists {
		for _, ns := range common.SliceCompact(nslist) {
			nsMap[ns] += 1
		}
	}

	res := []*Namespace{}
	for ns, count := range nsMap {
		if count == len(nslists) {
			res = append(res, ns)
		}
	}
	return res
}

func (ni *NamespacesInfo) GetConjunctionNamespaces(conj symbolicexpr.Term) []string {
	if cachedRes, ok := ni.cacheConjNamespaces[conj.String()]; ok {
		return cachedRes
	}
	ns := ni.conjNamespaces(conj)
	resStr := ni.namespacesStrings(ns)
	logging.Debug2f("input Term: %s, result namespaces: %v", conj.String(), resStr)
	ni.cacheConjNamespaces[conj.String()] = resStr
	return resStr
}

func (ni *NamespacesInfo) namespacesStrings(namespaces []*Namespace) []string {
	namespaces = common.SliceCompact(namespaces)
	// sort it by order of the namespacesInfo.namespaces
	slices.SortFunc(namespaces, func(n1, n2 *Namespace) int {
		return slices.Index(ni.Namespaces, n1) - slices.Index(ni.Namespaces, n2)
	})
	resStr := common.StringifiedSliceToStrings(namespaces)
	return resStr
}

/*
// GetConjunctionNamespaces() returns the namspaces of a Term
// since the Term is abstract, we:
// 1. obtain the list of VMs using the atom labels
// 2. find the namespaces of the VMs
func (ni *NamespacesInfo) GetConjunctionNamespacesOld(conj symbolicexpr.Term) []string {
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
			// for _, vm := range vms {
			// 	res = append(res, ni.vmNamespace[vm])
			// }
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
*/
