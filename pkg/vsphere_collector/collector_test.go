/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vsphere_collector

import (
	"fmt"
	"path"
	"testing"

	"github.com/np-guard/vmware-analyzer/pkg/common"
)

const (
	outDir = "out/"
)

//nolint:gocyclo // one function with lots of checks
func TestCollectResources(t *testing.T) {
	type args struct {
		server          string
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
			if tt.args.server == "no_server" {
				fmt.Println("didn't got any server")
				return
			}
			got, err := CollectResources(tt.args.server, tt.args.userName, tt.args.password)
			if err != nil {
				t.Errorf("CollectResources() error = %v", err)
				return
			}
			if got == nil {
				t.Errorf("didnt got resources")
				return
			}
			jsonOut, err := got.ToJSONString()
			if err != nil {
				t.Errorf("fail to convert to json error = %v", err)
				return
			}
			err = common.WriteToFile(path.Join(outDir, tt.name+".json"), jsonOut)
			if err != nil {
				t.Errorf("fail to write to file error = %v", err)
				return
			}
		})
	}
}
