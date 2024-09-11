/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"testing"
)

func TestCollectResources(t *testing.T) {
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
			got, err := CollectResources(tt.args.nsxServer, tt.args.userName, tt.args.password)
			if (err != nil) != (tt.args.nsxServer == "no_server") {
				t.Errorf("CollectResources() error = %v", err)
				return
			}
			if got != nil && len(got.SecurityPolicyList) == 0 {
				t.Errorf("didnt find SecurityPolicyList")
			}
			if got != nil && len(got.VirtualMachineList) == 0 {
				t.Errorf("didnt find VirtualMachineList")
			}
		})
	}
}
