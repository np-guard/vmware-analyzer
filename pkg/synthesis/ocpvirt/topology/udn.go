package topology

import udnv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"

func createUDNResource(name, namespace, cidr string) *udnv1.UserDefinedNetwork {
	res := &udnv1.UserDefinedNetwork{}
	res.Kind = "UserDefinedNetwork"
	res.APIVersion = "k8s.ovn.org/v1"
	res.Namespace = namespace
	res.Name = name
	res.Spec.Topology = udnv1.NetworkTopologyLayer2
	res.Spec.Layer2 = &udnv1.Layer2Config{
		Role:    udnv1.NetworkRolePrimary,
		Subnets: udnv1.DualStackCIDRs{udnv1.CIDR(cidr)},
		IPAM: &udnv1.IPAMConfig{
			Lifecycle: udnv1.IPAMLifecyclePersistent,
		},
	}
	return res
}

// todo: support NAD , CUDN, etc..
