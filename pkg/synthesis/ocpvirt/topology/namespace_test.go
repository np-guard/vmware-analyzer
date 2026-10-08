package topology

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netset"
	cfgTopology "github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/config"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

func TestNamespaceNameForSegmentUnmappedDefault(t *testing.T) {
	seg := newTestSegment("Seg-Web", "10.0.1.0/24", nil)
	ni := &NamespacesInfo{options: &config.SynthesisOptions{}}
	require.Equal(t, utils.ToLegalK8SString("Seg-Web"), ni.namespaceNameForSegment(seg))
}

func TestNamespaceNameForSegmentRename(t *testing.T) {
	seg := newTestSegment("Seg-Web", "10.0.1.0/24", nil)
	ni := &NamespacesInfo{options: &config.SynthesisOptions{
		SegmentNamespaceMap: map[string]string{"Seg-Web": "tom-testing"},
	}}
	require.Equal(t, "tom-testing", ni.namespaceNameForSegment(seg))
}

func TestNamespaceNameForSegmentTargetNamespace(t *testing.T) {
	seg := newTestSegment("Seg-Web", "10.0.1.0/24", nil)
	ni := &NamespacesInfo{options: &config.SynthesisOptions{
		TargetNamespace: "tom-testing",
	}}
	require.Equal(t, "tom-testing", ni.namespaceNameForSegment(seg))
}

func TestNamespaceNameForSegmentMapOverridesTargetNamespace(t *testing.T) {
	segWeb := newTestSegment("Seg-Web", "10.0.1.0/24", nil)
	segDB := newTestSegment("Seg-Database", "10.0.2.0/24", nil)
	ni := &NamespacesInfo{options: &config.SynthesisOptions{
		TargetNamespace: "tom-testing",
		SegmentNamespaceMap: map[string]string{
			"Seg-Database": "other-ns",
		},
	}}
	require.Equal(t, "tom-testing", ni.namespaceNameForSegment(segWeb))
	require.Equal(t, "other-ns", ni.namespaceNameForSegment(segDB))
}

func TestInitNamespacesTargetNamespaceCollapsesAll(t *testing.T) {
	vmWeb := cfgTopology.NewVM("web-1", "web-1")
	vmDB := cfgTopology.NewVM("db-1", "db-1")
	vmMgmt := cfgTopology.NewVM("mgmt-1", "mgmt-1")

	segWeb := newTestSegment("Seg-Web", "10.0.1.0/24", []cfgTopology.Endpoint{vmWeb})
	segDB := newTestSegment("Seg-Database", "10.0.2.0/24", []cfgTopology.Endpoint{vmDB})
	segMgmt := newTestSegment("Seg-Management", "10.0.3.0/24", []cfgTopology.Endpoint{vmMgmt})

	synthModel := &model.AbstractModelSyn{
		VMs:      []cfgTopology.Endpoint{vmWeb, vmDB, vmMgmt},
		Segments: []*cfgTopology.Segment{segWeb, segDB, segMgmt},
	}
	ni := newNamespacesInfo(synthModel, &config.SynthesisOptions{
		TargetNamespace: "tom-testing",
	})

	require.Len(t, ni.Namespaces, 1)
	require.Equal(t, "tom-testing", ni.Namespaces[0].Name)
	require.Equal(t, "tom-testing", ni.vmNamespace[vmWeb].Name)
	require.Equal(t, "tom-testing", ni.vmNamespace[vmDB].Name)
	require.Equal(t, "tom-testing", ni.vmNamespace[vmMgmt].Name)
	require.Same(t, ni.vmNamespace[vmWeb], ni.vmNamespace[vmMgmt])
}

func TestInitNamespacesCollapseAndUnmapped(t *testing.T) {
	vmWeb := cfgTopology.NewVM("web-1", "web-1")
	vmDB := cfgTopology.NewVM("db-1", "db-1")
	vmMgmt := cfgTopology.NewVM("mgmt-1", "mgmt-1")

	segWeb := newTestSegment("Seg-Web", "10.0.1.0/24", []cfgTopology.Endpoint{vmWeb})
	segDB := newTestSegment("Seg-Database", "10.0.2.0/24", []cfgTopology.Endpoint{vmDB})
	segMgmt := newTestSegment("Seg-Management", "10.0.3.0/24", []cfgTopology.Endpoint{vmMgmt})

	synthModel := &model.AbstractModelSyn{
		VMs:      []cfgTopology.Endpoint{vmWeb, vmDB, vmMgmt},
		Segments: []*cfgTopology.Segment{segWeb, segDB, segMgmt},
	}
	opts := &config.SynthesisOptions{
		SegmentNamespaceMap: map[string]string{
			"Seg-Web":      "tom-testing",
			"Seg-Database": "tom-testing",
			// Seg-Management intentionally unmapped
		},
	}

	ni := newNamespacesInfo(synthModel, opts)

	require.Len(t, ni.Namespaces, 2)
	require.Equal(t, "tom-testing", ni.Namespaces[0].Name)
	require.Equal(t, utils.ToLegalK8SString("Seg-Management"), ni.Namespaces[1].Name)

	require.Equal(t, "tom-testing", ni.vmNamespace[vmWeb].Name)
	require.Equal(t, "tom-testing", ni.vmNamespace[vmDB].Name)
	require.Equal(t, utils.ToLegalK8SString("Seg-Management"), ni.vmNamespace[vmMgmt].Name)

	// collapsed namespaces share one object
	require.Same(t, ni.vmNamespace[vmWeb], ni.vmNamespace[vmDB])

	ns := ni.createNamespaces()
	require.Len(t, ns, 2)
	require.Equal(t, "tom-testing", ns[0].Name)
	require.Equal(t, "tom-testing", ns[0].Labels["kubernetes.io/metadata.name"])
}

func TestGetConjunctionNamespacesUsesMappedNames(t *testing.T) {
	vmWeb := cfgTopology.NewVM("web-1", "web-1")
	vmDB := cfgTopology.NewVM("db-1", "db-1")
	segWeb := newTestSegment("Seg-Web", "10.0.1.0/24", []cfgTopology.Endpoint{vmWeb})
	segDB := newTestSegment("Seg-Database", "10.0.2.0/24", []cfgTopology.Endpoint{vmDB})

	synthModel := &model.AbstractModelSyn{
		VMs:      []cfgTopology.Endpoint{vmWeb, vmDB},
		Segments: []*cfgTopology.Segment{segWeb, segDB},
	}
	opts := &config.SynthesisOptions{
		SegmentNamespaceMap: map[string]string{
			"Seg-Web":      "tom-testing",
			"Seg-Database": "tom-testing",
		},
	}
	opts.PolicyOptimizationLevel.SetDefault()

	ni := newNamespacesInfo(synthModel, opts)
	names := ni.namespacesStrings(ni.Namespaces)
	require.Equal(t, []string{"tom-testing"}, names)
	require.NotContains(t, names, "Seg-Web")
	require.NotContains(t, names, "Seg-Database")
}

func newTestSegment(name, cidr string, vms []cfgTopology.Endpoint) *cfgTopology.Segment {
	block, err := netset.IPBlockFromCidr(cidr)
	if err != nil {
		panic(err)
	}
	seg := cfgTopology.NewSegment(name, block, []string{cidr})
	seg.VMs = vms
	return seg
}
