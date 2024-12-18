package model

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

const (
	outDir = "out/"
)

func Test_verifyTraceflow(t *testing.T) {
	type args struct {
		nsxServer          string
		userName, password string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"simple",
			args{
				// you can set your server info here:
				"no_server",
				"no_user",
				"no_password",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.nsxServer == "no_server" {
				if os.Getenv("NSX_HOST") == "" {
					fmt.Println("didn't got any server")
					return
				}
				tt.args = args{os.Getenv("NSX_HOST"), os.Getenv("NSX_USER"), os.Getenv("NSX_PASSWORD")}
			}
			server := collector.NewServerData(tt.args.nsxServer, tt.args.userName, tt.args.password)
			got, err := collector.CollectResources(server)
			if err != nil {
				t.Errorf("CollectResources() error = %v", err)
				return
			}
			if got == nil {
				t.Errorf("didnt got resources")
				return
			}
			filter := func(vm *endpoints.VM) bool { return strings.Contains(vm.Name(), "New") }
			tfs, err := compareConfigToTraceflows(got, server, filter)
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
		})
	}
}
