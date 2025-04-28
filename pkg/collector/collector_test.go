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

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

const (
	outDir = "out/"
)

func TestGroupCollection(t *testing.T) {
	server, err := GetNSXServerDate("", "", "", true)
	if err != nil {
		// do not fail on env without access to nsx host
		fmt.Println(err.Error())
		return
	}
	group := &Group{}
	query := "policy/api/v1/infra/domains/default/groups/ex12-expr-with-2-conditions"
	err = collectResource(server, query, group)
	require.Nil(t, err)
	s, err := common.MarshalJSON(group)
	require.Nil(t, err)
	fmt.Printf("%s\n", s)
	fmt.Println("done")
}

//nolint:gocyclo // one function with lots of checks
func TestCollectResources(t *testing.T) {
	args := struct {
		nsxServer          string
		userName, password string
	}{
		// you can set your server info here
	}
	require.Nil(t, logging.Init(logging.HighVerbosity, ""))
	server, err := GetNSXServerDate(args.nsxServer, args.userName, args.password, true)
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
						_, err := common.IPBlockFromCidrOrAddressOrIPRange(ref)
						if err != nil && domainResource.GetGroup(ref) == nil {
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
	fileName := path.Join(outDir, "resources.json")
	fileName2 := path.Join(outDir, "resources2.json")
	err = common.WriteToFile(fileName, jsonOut)
	if err != nil {
		t.Errorf("failed in write to file: error = %v", err)
		return
	}
	b, err := os.ReadFile(fileName)
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
	err = common.WriteToFile(path.Join(outDir, fileName2), jsonOut2)
	if err != nil {
		t.Errorf("failed in write to file: error = %v", err)
		return
	}
	if jsonOut != jsonOut2 {
		t.Errorf("conversion from json returns another object")
		return
	}

	logging.Debugf("done")
}
