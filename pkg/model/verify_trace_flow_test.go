package model

import (
	"fmt"
	"path"
	"testing"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
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
				"no_server",
				"no_user",
				"no_password",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.nsxServer == "no_server" {
				fmt.Println("didn't got any server")
				return
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
			tfs, err := verifyTraceflow(got, server)
			if err != nil {
				t.Errorf("verifyTraceflow() error = %v", err)
			}
			jOut, err := tfs.ToJSONString()
			if err != nil {
				t.Errorf("ToJSONString() error = %v", err)
			}
			if err := common.WriteToFile(path.Join(outDir, "traceflowsObservations.json"), jOut); err != nil {
				t.Errorf("ToJSONString() error = %v", err)
			}
		})
	}
}
