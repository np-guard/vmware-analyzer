/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vsphrcoll

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

const (
	outDir = "out/"
)

func TestCollectResources(t *testing.T) {
	type args struct {
		server             string
		userName, password string
		insecureSkipVerify bool
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
				true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.server == "no_server" {
				if os.Getenv("VSPHERE_HOST") == "" {
					fmt.Println(common.ErrNoHostArg)
					return
				}
				tt.args = args{os.Getenv("VSPHERE_HOST"), os.Getenv("VSPHERE_USER"), os.Getenv("VSPHERE_PASSWORD"), true}
			}
			got, err := CollectResources(tt.args.server, tt.args.userName, tt.args.password, tt.args.insecureSkipVerify)
			if err != nil {
				t.Errorf("CollectResources() error = %v", err)
				return
			}
			if got == nil {
				t.Errorf(common.ErrNoResources)
				return
			}
			jsonOut, err := got.ToJSONString()
			if err != nil {
				t.Errorf("failed to convert to json error = %v", err)
				return
			}
			err = common.WriteToFile(path.Join(outDir, tt.name+".json"), jsonOut)
			if err != nil {
				t.Errorf("failed to write to file error = %v", err)
				return
			}
		})
	}
}
