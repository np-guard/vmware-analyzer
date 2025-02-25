package runner

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
)

// Observations holds reference to runner that completed its run without err.
// It captures output/observations produced from a successful run.
type Observations struct {
	r *Runner
}

// JSONResults holds various JSON strings for NSX config/anslysis/synthesis
type JSONResults struct {
	Topology         string
	Segmentation     string
	Connectivity     string
	GeneratedNetpols string
}

// ConfigAsJSON returns JSONResults objects, capruting various NSX config/anslysis/synthesis data in JSON strings format.
func (o *Observations) ConfigAsJSON() (res *JSONResults, err error) {
	res = &JSONResults{}

	// topology
	if res.Topology, err = o.r.parsedConfig.TopologyToJSON(); err != nil {
		return nil, err
	}

	// segmentation
	segmentation := o.r.nsxResources.DomainList[0].Resources.SecurityPolicyList
	if res.Segmentation, err = common.MarshalJSON(segmentation); err != nil {
		return nil, err
	}

	// connectivity
	if res.Connectivity, err = o.r.analyzedConnectivity.GenConnectivityOutput(common.OutputParameters{Format: common.JSONFormat}); err != nil {
		return nil, err
	}

	// generated netpols
	// TODO: add also admin netpols
	if res.GeneratedNetpols, err = common.MarshalJSON(o.r.generatedK8sPolicies); err != nil {
		return nil, err
	}

	return res, nil
}
