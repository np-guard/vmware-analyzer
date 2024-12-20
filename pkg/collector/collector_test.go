/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/np-guard/vmware-analyzer/pkg/common"
)

const (
	outDir = "out/"
)

//nolint:gocyclo // one function with lots of checks
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
			server := NewServerData(tt.args.nsxServer, tt.args.userName, tt.args.password)
			got, err := CollectResources(server)
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
			for _, service := range got.ServiceList {
				for _, e := range service.ServiceEntries {
					//nolint:errcheck // we do not support all services
					e.ToConnection()
				}
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
								s := got.GetService(ref)
								if s == nil {
									t.Errorf("fail to find service of %v", ref)
									return
								}
								for _, e := range s.ServiceEntries {
									_, err := e.ToConnection()
									if err != nil {
										if !strings.Contains(err.Error(), "protocol ICMPv6 of ICMPTypeServiceEntry") {
											t.Errorf("fail to create rule service entry error = %v", err)
											return
										}
									}
								}
							}
						}
						ServiceEntries := domainResource.SecurityPolicyList[spi].Rules[ri].ServiceEntries
						for _, e := range ServiceEntries {
							_, err := e.ToConnection()
							if err != nil {
								t.Errorf("fail to create rule service entry = %v", err)
								return
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
			err = common.WriteToFile(path.Join(outDir, tt.name+".json"), jsonOut)
			if err != nil {
				t.Errorf("fail to write to file error = %v", err)
				return
			}
			b, err := os.ReadFile(path.Join(outDir, tt.name+".json"))
			if err != nil {
				t.Errorf("fail to read from file error = %v", err)
				return
			}
			got2, err := FromJSONString(b)
			if err != nil {
				t.Errorf("fail to convert from json error = %v", err)
				return
			}
			jsonOut2, err := got2.ToJSONString()
			if err != nil {
				t.Errorf("fail to convert to json error = %v", err)
				return
			}
			err = common.WriteToFile(path.Join(outDir, tt.name+"2.json"), jsonOut2)
			if err != nil {
				t.Errorf("fail to write to file error = %v", err)
				return
			}
			if jsonOut != jsonOut2 {
				t.Errorf("convering from json returns another object")
				return
			}
		})
	}
}
