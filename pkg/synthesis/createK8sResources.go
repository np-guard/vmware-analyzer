package synthesis

import (
	"path"


	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

const k8sAPIVersion = "networking.k8s.io/v1"

func createK8sResources(model *AbstractModelSyn, outDir string) error {
	policies := toNetworkPolicies(model)
	policiesFileName := path.Join(outDir, "policies.yaml")
	if err := common.WriteYamlUsingJSON(policies, policiesFileName); err != nil {
		return err
	}
	pods := toPods(model)
	podsFileName := path.Join(outDir, "pods.yaml")
	if err := common.WriteYamlUsingJSON(pods, podsFileName); err != nil {
		return err
	}
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

func toNetworkPolicies(model *AbstractModelSyn) []*networking.NetworkPolicy {
	policies := newK8sPolicies(false)
	for _, p := range model.policy {
		for _, ob := range p.outbound {
			for _, p := range ob.allowOnlyRulePaths {
				policies.addNewPolicy(p,false)
			}
		}
		for _, ib := range p.inbound {
			for _, p := range ib.allowOnlyRulePaths {
				policies.addNewPolicy(p,true)
			}
		}
	}
	return policies.toNetworkPolicies()
}


func newAdminNetworkPolicy(name, description string) *admin.AdminNetworkPolicy {
	pol := &admin.AdminNetworkPolicy{}
	pol.TypeMeta.Kind = "AdminNetworkPolicy"
	pol.TypeMeta.APIVersion = k8sAPIVersion
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{"description": description}
	return pol
}



func toSelectorsAndPorts(p *symbolicexpr.SymbolicPath) (srcSelector, dstSelector *meta.LabelSelector,
	ports k8sPorts, empty bool) {
	srcSelector = toSelector(p.Src)
	dstSelector = toSelector(p.Dst)
	ports, empty = toPolicyPorts(p.Conn)
	return
}

var codeToProtocol = map[int]core.Protocol{netset.UDPCode: core.ProtocolUDP, netset.TCPCode: core.ProtocolTCP}
var boolToOperator = map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}

func pointerTo[T any](t T) *T {
	return &t
}

func toSelector(con symbolicexpr.Conjunction) *meta.LabelSelector {
	selector := &meta.LabelSelector{}
	for _, a := range con {
		label, notIn := a.AsSelector()
		if label != "" { // not tautology
			req := meta.LabelSelectorRequirement{Key: label, Operator: boolToOperator[notIn]}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		}
	}
	return selector
}

func toPolicyPorts(conn *netset.TransportSet) (k8sPorts, bool) {
	ports := newK8sPorts(false)
	tcpUDPSet := conn.TCPUDPSet()
	if tcpUDPSet.IsEmpty() {
		return nil, true
	}
	if tcpUDPSet.IsAll() {
		return ports, false
	}
	partitions := tcpUDPSet.Partitions()
	for _, partition := range partitions {
		protocols := partition.S1.Elements()
		portRanges := partition.S3
		for _, portRange := range portRanges.Intervals() {
			ports.addPorts(portRange.Start(),portRange.End(),protocols)
		}
	}
	return ports, false
}

// ///////////////////////////////////////////////////////////////////////////////
func toPods(model *AbstractModelSyn) []*core.Pod {
	pods := []*core.Pod{}
	for _, vm := range model.vms {
		pod := &core.Pod{}
		pod.TypeMeta.Kind = "Pod"
		pod.TypeMeta.APIVersion = k8sAPIVersion
		pod.ObjectMeta.Name = vm.Name()
		pod.ObjectMeta.UID = types.UID(vm.ID())
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
