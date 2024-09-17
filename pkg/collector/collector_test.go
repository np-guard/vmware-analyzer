/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	writeFileMde = 0o600
)
const (
	outDir = "out/"
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
			if tt.args.nsxServer == "no_server" {
				fmt.Println("didn got any server")
				return
			}
			got, err := CollectResources(tt.args.nsxServer, tt.args.userName, tt.args.password)
			if err != nil {
				t.Errorf("CollectResources() error = %v", err)
				return
			}
			if got == nil {
				t.Errorf("didnt got resources")
				return
			}
			if len(got.VirtualMachineList) == 0 {
				t.Errorf("didnt find VirtualMachineList")
			}
			for _, domain := range got.DomainList {
				domainResource := domain.Resources
				if len(domainResource.SecurityPolicyList) == 0 {
					t.Errorf("didnt find SecurityPolicyList")
				}
				if len(domainResource.GroupList) == 0 {
					t.Errorf("didnt find Groups")
				}
				for spi := range domainResource.SecurityPolicyList {
					for ri := range domainResource.SecurityPolicyList[spi].Rules {
						sGroups := domainResource.SecurityPolicyList[spi].Rules[ri].SourceGroups
						dGroups := domainResource.SecurityPolicyList[spi].Rules[ri].DestinationGroups
						for _, ref := range append(sGroups, dGroups...) {
							if ref != "ANY" {
								if domainResource.GetGroup(ref) == nil {
									t.Errorf("fail to find group of %v", ref)
									return
								}
							}
						}
						services := domainResource.SecurityPolicyList[spi].Rules[ri].Services
						for _, ref := range services {
							if ref != "ANY" {
								if got.GetService(ref) == nil {
									t.Errorf("fail to find service of %v", ref)
									return
								}
							}
						}
					}
				}
			}
			jsonOut, err := got.ToJSONString()
			if err != nil {
				t.Errorf("fail to convert to json error = %v", err)
				return
			}
			err = writTeToFile(outDir, tt.name+".json", jsonOut)
			if err != nil {
				t.Errorf("fail to write to file error = %v", err)
				return
			}
		})
	}
}

// todo - move this func to more general place, and make it more generic
func writTeToFile(dir, name, content string) error {
	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}
	currentOutDir := filepath.Join(currentDir, dir)
	err = os.MkdirAll(currentOutDir, os.ModePerm)
	if err != nil {
		return err
	}
	fileName := filepath.Join(dir, name)
	return os.WriteFile(fileName, []byte(content), writeFileMde)
}
