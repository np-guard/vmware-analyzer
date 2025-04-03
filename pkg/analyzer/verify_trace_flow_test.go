package analyzer

import (
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"

	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

const (
	outDir = "out/"
)

func Test_verifyTraceflow(t *testing.T) {
	args := struct {
		nsxServer          string
		userName, password string
	}{
		// you can set your server info here
	}
	require.Nil(t, logging.Init(logging.HighVerbosity, path.Join(outDir, "traceflows.log")))
	server, err := collector.GetNSXServerDate(args.nsxServer, args.userName, args.password, true)
	if err != nil {
		// do not fail on env without access to nsx host
		fmt.Println(err.Error())
		return
	}
	collectedResources, err := collector.CollectResources(server)
	if err != nil {
		t.Errorf("CollectResources() error = %v", err)
		return
	}
	if collectedResources == nil {
		t.Errorf(common.ErrNoResources)
		return
	}
	filter := func(vm topology.Endpoint) bool { return strings.Contains(vm.Name(), "") }
	tfs, err := compareConfigToTraceflows(collectedResources, server, filter)
	if err != nil {
		t.Errorf("verifyTraceflow() error = %v", err)
	}
	jOut, err := tfs.ToJSONString()
	if err != nil {
		t.Errorf("ToJSONString() error = %v", err)
	}
	tfPath := path.Join(outDir, "traceflowsObservations.json")
	if err := common.WriteToFile(tfPath, jOut); err != nil {
		t.Errorf("ToJSONString() error = %v", err)
	}
	fmt.Printf("traceflow results at %s\n", tfPath)
	fmt.Printf("done")
}
