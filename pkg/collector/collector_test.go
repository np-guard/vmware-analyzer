/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"fmt"
	"os"
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
			testTopology(got)
			testTree(got)
			for _, service := range got.ServiceList {
				for _, e := range service.ServiceEntries {
					//nolint:errcheck // we do not support al services?
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
										t.Errorf("fail to create rule service entry error = %v", err)
										return
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


func testTopology(got *ResourcesContainerModel) {
	for _, segment := range got.SegmentList {
		fmt.Printf("--------------------- segment(type) %s(%s) ------------------\n", *segment.DisplayName, *segment.Type)

		if segment.ConnectivityPath == nil{
			fmt.Printf("segment(type) %s(%s) has no ConnectivityPath\n", *segment.DisplayName, *segment.Type)
		} else if t1 := got.GetTier1(*segment.ConnectivityPath); t1 != nil{
			t0 := got.GetTier0(*t1.Tier0Path)
			fmt.Printf("[segment(type), t1, t0]: [%s(%s), %s, %s]\n", *segment.DisplayName, *segment.Type, *t1.DisplayName, *t0.DisplayName)
		}else if t0 := got.GetTier0(*segment.ConnectivityPath); t0 != nil{
			fmt.Printf("[segment(type), t0]: [%s(%s), %s]\n", *segment.DisplayName, *segment.Type, *t0.DisplayName)
		}else{
			fmt.Printf("fail to find tier of segment(type): %s(%s) with connectivity %s\n", *segment.DisplayName, *segment.Type, *segment.ConnectivityPath)
		}
		if len(segment.SegmentPorts) == 0{
			fmt.Printf("segment(type) %s(%s) has no ports\n", *segment.DisplayName, *segment.Type)
		}
		for _, port := range segment.SegmentPorts {
			att := *port.Attachment.Id
			vif := got.GetVirtualNetworkInterfaceByPort(att)
			vm := got.GetVirtualMachine(*vif.OwnerVmId)
			fmt.Printf("[segment(type), vm]: [%s(%s), %s]\n", *segment.DisplayName, *segment.Type, *vm.DisplayName)
		}
		
	}
}
