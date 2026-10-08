package synthesis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/internal/test_utils"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/topology"
)

// Real Desktop NSX export copied under testdata for local/container verification.
// Full generate currently panics in allow-only flattening on this dump (nil symbolic atom);
// this test validates target-namespace against the real segment topology only.
func TestTargetNamespaceAgainstDesktopNSXExport(t *testing.T) {
	test_utils.LogInit(t, "")
	exportPath := filepath.Join("..", "..", "testdata", "nsx-export", "nsx-resources-2.json")
	if !common.FileExist(exportPath) {
		// also try from module root when tests run with different cwd
		exportPath = filepath.Join("testdata", "nsx-export", "nsx-resources-2.json")
	}
	if !common.FileExist(exportPath) {
		t.Skipf("NSX export not found at %s", exportPath)
	}

	b, err := os.ReadFile(exportPath)
	require.NoError(t, err)
	rc, err := collector.FromJSONString(b)
	require.NoError(t, err)
	nsxConfig, err := configuration.ConfigFromResourcesContainer(rc, &common.OutputParameters{})
	require.NoError(t, err)
	require.NotEmpty(t, nsxConfig.Topology.Segments)

	segNames := make([]string, 0, len(nsxConfig.Topology.Segments))
	for _, s := range nsxConfig.Topology.Segments {
		segNames = append(segNames, s.Name)
	}
	require.Contains(t, segNames, "Seg-Web")
	require.Contains(t, segNames, "Seg-Database")
	require.Contains(t, segNames, "Seg-Management")

	abstract := &model.AbstractModelSyn{
		VMs:      nsxConfig.VMs,
		Segments: nsxConfig.Topology.Segments,
	}

	t.Run("default_uses_segment_names", func(t *testing.T) {
		opts := &config.SynthesisOptions{Hints: &symbolicexpr.Hints{}}
		opts.EndpointsMapping.SetDefault()
		opts.SegmentsMapping.SetDefault()
		opts.PolicyOptimizationLevel.SetDefault()

		gen := topology.NewNetworkTopologyGenerator(abstract, opts)
		gen.Generate()
		nsNames := namespaceNames(gen)
		require.ElementsMatch(t, []string{"Seg-Web", "Seg-Database", "Seg-Management"}, nsNames)
	})

	t.Run("target_namespace_collapses_all", func(t *testing.T) {
		opts := &config.SynthesisOptions{
			Hints:           &symbolicexpr.Hints{},
			TargetNamespace: "tom-testing",
		}
		opts.EndpointsMapping.SetDefault()
		opts.SegmentsMapping.SetDefault()
		opts.PolicyOptimizationLevel.SetDefault()

		gen := topology.NewNetworkTopologyGenerator(abstract, opts)
		gen.Generate()
		nsNames := namespaceNames(gen)
		require.Equal(t, []string{"tom-testing"}, nsNames)

		for _, pod := range gen.Pods {
			require.Equal(t, "tom-testing", pod.Namespace, "pod %s", pod.Name)
		}
		for _, vm := range gen.VMs {
			require.Equal(t, "tom-testing", vm.Namespace, "vm %s", vm.Name)
		}
		// VLAN segments in this export have empty CIDRs, so UDN may be skipped —
		// but if any UDN is emitted it must use the mapped namespace.
		for _, udn := range gen.UDNs {
			require.Equal(t, "tom-testing", udn.Namespace)
			require.Equal(t, "udn-tom-testing", udn.Name)
		}
	})
}

func namespaceNames(gen *topology.NetworkTopologyGenerator) []string {
	res := make([]string, 0, len(gen.Namespaces))
	for _, ns := range gen.Namespaces {
		res = append(res, ns.Name)
	}
	return res
}
