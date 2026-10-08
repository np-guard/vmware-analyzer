package synthesis

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/np-guard/vmware-analyzer/pkg/data"
	"github.com/np-guard/vmware-analyzer/pkg/internal/test_utils"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt"
)

func segmentNamespaceMapOptions(m map[string]string) *config.SynthesisOptions {
	opts := &config.SynthesisOptions{
		Hints:               &symbolicexpr.Hints{},
		SegmentNamespaceMap: m,
	}
	opts.EndpointsMapping.SetDefault()
	opts.SegmentsMapping.SetDefault()
	opts.PolicyOptimizationLevel.SetDefault()
	return opts
}

func TestTargetNamespaceCollapsesAllPeers(t *testing.T) {
	test_utils.LogInit(t, "")
	rc, err := data.ExamplesGeneration(data.Example1dExternalWithSegments, false)
	require.NoError(t, err)

	opts := segmentNamespaceMapOptions(nil)
	opts.TargetNamespace = "tom-testing"
	opts.CreateDNSPolicy = true

	generated, err := ocpvirt.NSXToK8sSynthesis(rc, nil, opts)
	require.NoError(t, err)

	require.Len(t, generated.Namespaces, 1)
	require.Equal(t, "tom-testing", generated.Namespaces[0].Name)

	forbidden := []string{"seg_a_and_b", "seg_c"}
	for _, pol := range generated.NetworkPolicies {
		require.Equal(t, "tom-testing", pol.Namespace, "policy %s", pol.Name)
		requireNoForbiddenNamespacePeers(t, pol, forbidden)
	}
}

func TestSegmentNamespaceMapCollapsePeers(t *testing.T) {
	test_utils.LogInit(t, "")
	rc, err := data.ExamplesGeneration(data.Example1dExternalWithSegments, false)
	require.NoError(t, err)

	opts := segmentNamespaceMapOptions(map[string]string{
		"seg_a_and_b": "tom-testing",
		"seg_c":       "tom-testing",
	})
	opts.CreateDNSPolicy = true

	generated, err := ocpvirt.NSXToK8sSynthesis(rc, nil, opts)
	require.NoError(t, err)

	require.Len(t, generated.Namespaces, 1)
	require.Equal(t, "tom-testing", generated.Namespaces[0].Name)

	for _, udn := range generated.UDNs {
		require.Equal(t, "tom-testing", udn.Namespace)
		require.Equal(t, "udn-tom-testing", udn.Name)
	}
	for _, pod := range generated.Pods {
		require.Equal(t, "tom-testing", pod.Namespace)
	}
	for _, vm := range generated.VMs {
		require.Equal(t, "tom-testing", vm.Namespace)
	}

	forbidden := []string{"seg_a_and_b", "seg_c"}
	for _, pol := range generated.NetworkPolicies {
		require.Equal(t, "tom-testing", pol.Namespace, "policy %s", pol.Name)
		if strings.HasPrefix(pol.Name, "default-deny-for-") {
			require.Equal(t, "default-deny-for-tom-testing", pol.Name)
		}
		if strings.HasPrefix(pol.Name, "dns-policy-") {
			require.Equal(t, "dns-policy-tom-testing", pol.Name)
		}
		requireNoForbiddenNamespacePeers(t, pol, forbidden)
	}
}

func TestSegmentNamespaceMapSingleRename(t *testing.T) {
	test_utils.LogInit(t, "")
	rc, err := data.ExamplesGeneration(data.Example1dExternalWithSegments, false)
	require.NoError(t, err)

	opts := segmentNamespaceMapOptions(map[string]string{
		"seg_a_and_b": "web-ns",
		// seg_c unmapped → legalized segment name
	})

	generated, err := ocpvirt.NSXToK8sSynthesis(rc, nil, opts)
	require.NoError(t, err)

	nsNames := map[string]bool{}
	for _, ns := range generated.Namespaces {
		nsNames[ns.Name] = true
	}
	require.True(t, nsNames["web-ns"])
	require.True(t, nsNames["seg_c"])
	require.False(t, nsNames["seg_a_and_b"])

	foundCrossNSPeer := false
	for _, pol := range generated.NetworkPolicies {
		require.NotEqual(t, "seg_a_and_b", pol.Namespace)
		for _, peerNS := range collectNamespacePeerValues(pol) {
			require.NotEqual(t, "seg_a_and_b", peerNS)
			if peerNS == "web-ns" || peerNS == "seg_c" {
				foundCrossNSPeer = true
			}
		}
	}
	require.True(t, foundCrossNSPeer, "expected peer selectors to reference mapped/unmapped namespaces")
}

func requireNoForbiddenNamespacePeers(t *testing.T, pol *networkingv1.NetworkPolicy, forbidden []string) {
	t.Helper()
	for _, peerNS := range collectNamespacePeerValues(pol) {
		for _, f := range forbidden {
			require.NotEqual(t, f, peerNS, "policy %s peer still references segment namespace %s", pol.Name, f)
		}
	}
}

func collectNamespacePeerValues(pol *networkingv1.NetworkPolicy) []string {
	var values []string
	collect := func(peers []networkingv1.NetworkPolicyPeer) {
		for _, peer := range peers {
			if peer.NamespaceSelector == nil {
				continue
			}
			for _, expr := range peer.NamespaceSelector.MatchExpressions {
				if expr.Key == "kubernetes.io/metadata.name" {
					values = append(values, expr.Values...)
				}
			}
			for k, v := range peer.NamespaceSelector.MatchLabels {
				if k == "kubernetes.io/metadata.name" {
					values = append(values, v)
				}
			}
		}
	}
	for _, rule := range pol.Spec.Ingress {
		collect(rule.From)
	}
	for _, rule := range pol.Spec.Egress {
		collect(rule.To)
	}
	return values
}
