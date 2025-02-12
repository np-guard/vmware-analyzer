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

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
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
				// you can set your server info here, or specify through env vars
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Nil(t, logging.Init(logging.HighVerbosity, ""))
			server, err := GetNSXServerDate(tt.args.nsxServer, tt.args.userName, tt.args.password)
			if err != nil {
				// do not fail on env without access to nsx host
				fmt.Println(err.Error())
				return
			}
			collectedResources, err := CollectResources(server)
			if err != nil {
				t.Errorf("CollectResources() error = %v", err)
				return
			}
			if collectedResources == nil {
				t.Errorf(common.ErrNoResources)
				return
			}
			if len(collectedResources.VirtualMachineList) == 0 {
				t.Errorf("empty VirtualMachineList")
			}
			for _, service := range collectedResources.ServiceList {
				for _, e := range service.ServiceEntries {
					//nolint:errcheck // we do not support all services
					e.ToConnection()
				}
			}
			for _, domain := range collectedResources.DomainList {
				domainResource := domain.Resources
				if len(domainResource.SecurityPolicyList) == 0 {
					t.Errorf("empty SecurityPolicyList")
				}
				if len(domainResource.GroupList) == 0 {
					t.Errorf("empty GroupList")
				}
				for spi := range domainResource.SecurityPolicyList {
					for ri := range domainResource.SecurityPolicyList[spi].Rules {
						sGroups := domainResource.SecurityPolicyList[spi].Rules[ri].SourceGroups
						dGroups := domainResource.SecurityPolicyList[spi].Rules[ri].DestinationGroups
						for _, ref := range append(sGroups, dGroups...) {
							if ref != "ANY" {
								if domainResource.GetGroup(ref) == nil {
									t.Errorf("failed to find group of %v", ref)
									return
								}
							}
						}
						services := domainResource.SecurityPolicyList[spi].Rules[ri].Services
						for _, ref := range services {
							if ref != "ANY" {
								s := collectedResources.GetService(ref)
								if s == nil {
									t.Errorf("failed to find service of %v", ref)
									return
								}
								for _, e := range s.ServiceEntries {
									_, err := e.ToConnection()
									if err != nil {
										if !strings.Contains(err.Error(), "protocol ICMPv6 of ICMPTypeServiceEntry") {
											t.Errorf("failed to create rule service entry error = %v", err)
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
								t.Errorf("failed to create rule service entry = %v", err)
								return
							}
						}
					}
				}
			}
			jsonOut, err := collectedResources.ToJSONString()
			if err != nil {
				t.Errorf("failed in converting to json: error = %v", err)
				return
			}
			err = common.WriteToFile(path.Join(outDir, tt.name+".json"), jsonOut)
			if err != nil {
				t.Errorf("failed in write to file: error = %v", err)
				return
			}
			b, err := os.ReadFile(path.Join(outDir, tt.name+".json"))
			if err != nil {
				t.Errorf("failed in read from file: error = %v", err)
				return
			}
			got2, err := FromJSONString(b)
			if err != nil {
				t.Errorf("fail in converting from json: error = %v", err)
				return
			}
			jsonOut2, err := got2.ToJSONString()
			if err != nil {
				t.Errorf("fail in converting to json: error = %v", err)
				return
			}
			err = common.WriteToFile(path.Join(outDir, tt.name+"2.json"), jsonOut2)
			if err != nil {
				t.Errorf("failed in write to file: error = %v", err)
				return
			}
			if jsonOut != jsonOut2 {
				t.Errorf("conversion from json returns another object")
				return
			}

			logging.Debugf("done")
		})
	}
}
