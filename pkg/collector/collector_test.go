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
			if err := testTraceflows(got, server); err != nil{
				t.Errorf("testTraceflows() error = %v", err)
				return
			}
			testTopology(got)
			if err := dotTopology(got); err != nil {
				t.Errorf("dotTopology() error = %v", err)
				return
			}
			if err := dotConnections(got); err != nil {
				t.Errorf("dotConnections() error = %v", err)
				return
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

func testTopology(got *ResourcesContainerModel) {
	for si := range got.SegmentList {
		segment := &got.SegmentList[si]
		fmt.Printf("--------------------- segment(type)[addr] %s ------------------\n", segmentName(segment))

		if segment.ConnectivityPath == nil {
			fmt.Printf("segment(type)[addr] %s has no ConnectivityPath\n", segmentName(segment))
		} else if t1 := got.GetTier1(*segment.ConnectivityPath); t1 != nil {
			t0 := got.GetTier0(*t1.Tier0Path)
			fmt.Printf("[segment(type)[addr], t1, t0]: [%s, %s, %s]\n", segmentName(segment), *t1.DisplayName, *t0.DisplayName)
		} else if t0 := got.GetTier0(*segment.ConnectivityPath); t0 != nil {
			fmt.Printf("[segment(type)[addr], t0]: [%s, %s]\n", segmentName(segment), *t0.DisplayName)
		} else {
			fmt.Printf("fail to find tier of segment(type)[addr]: %s with connectivity %s\n", segmentName(segment), *segment.ConnectivityPath)
		}
		if len(segment.SegmentPorts) == 0 {
			fmt.Printf("segment(type)[addr] %s has no ports\n", segmentName(segment))
		}
		for pi := range segment.SegmentPorts {
			att := *segment.SegmentPorts[pi].Attachment.Id
			vif := got.GetVirtualNetworkInterfaceByPort(att)
			fmt.Printf("[segment(type)[addr], vm]: [%s, %s]\n", segmentName(segment), vniName(got, vif))
		}
	}
}

func testTraceflows(got *ResourcesContainerModel, server ServerData) error{
	ips := []string{
		"192.168.1.1",
		"192.168.1.2",
		"10.127.131.73",
		"192.168.1.3",
		"192.0.1.3",
	}
	tfs := getTraceFlows(got, server, ips)
	g := traceFlowsDotGraph(got, ips, tfs)
	_, err := common.OutputGraph(g, path.Join(outDir, "traceflow.dot"), common.DotFormat)
	return err
}

func dotTopology(got *ResourcesContainerModel) error {
	out := "digraph D {\n"
	for t1i := range got.Tier1List {
		t0 := got.GetTier0(*got.Tier1List[t1i].Tier0Path)
		out += fmt.Sprintf("\"t1:%s\" -> \"t0:%s\"\n", *got.Tier1List[t1i].DisplayName, *t0.DisplayName)
	}
	for si := range got.SegmentList {
		segment := &got.SegmentList[si]
		if segment.ConnectivityPath == nil {
		} else if t1 := got.GetTier1(*segment.ConnectivityPath); t1 != nil {
			out += fmt.Sprintf("\"sg:%s\" -> \"t1:%s\"\n", segmentName(segment), *t1.DisplayName)
		} else if t0 := got.GetTier0(*segment.ConnectivityPath); t0 != nil {
			out += fmt.Sprintf("\"sg:%s\" -> \"t0:%s\"\n", segmentName(segment), *t0.DisplayName)
		}
		for pi := range segment.SegmentPorts {
			att := *segment.SegmentPorts[pi].Attachment.Id
			vif := got.GetVirtualNetworkInterfaceByPort(att)
			out += fmt.Sprintf("\"ni:%s\" -> \"sg:%s\"\n", vniName(got, vif), segmentName(segment))
			vm := got.GetVirtualMachine(*vif.OwnerVmId)
			out += fmt.Sprintf("\"vm:%s\" -> \"ni:%s\"\n", *vm.DisplayName, vniName(got, vif))
		}
	}
	out += "}\n"
	return common.WriteToFile(path.Join(outDir, "topology.dot"), out)
}

func dotConnections(got *ResourcesContainerModel) error {
	out := "digraph D {\n"

	for i1 := range got.VirtualNetworkInterfaceList {
		for i2 := range got.VirtualNetworkInterfaceList {
			v1 := &got.VirtualNetworkInterfaceList[i1]
			v2 := &got.VirtualNetworkInterfaceList[i2]
			if i1 > i2 && IsConnected(got, v1, v2) {
				out += fmt.Sprintf("%q -> %q[dir=none]\n", vniName(got, v1), vniName(got, v2))
			}
		}
	}
	out += "}\n"
	return common.WriteToFile(path.Join(outDir, "connection.dot"), out)
}

func vniName(resources *ResourcesContainerModel, vni *VirtualNetworkInterface) string {
	addresses := []string{}
	for _, ai := range vni.IpAddressInfo {
		for _, a := range ai.IpAddresses {
			addresses = append(addresses, string(a))
		}
	}
	return fmt.Sprintf("%s\\n[%s]", *resources.GetVirtualMachine(*vni.OwnerVmId).DisplayName, strings.Join(addresses, ","))
}

func segmentName(segment *Segment) string {
	nAddresses := []string{}
	for _, subnet := range segment.Subnets {
		nAddresses = append(nAddresses, *subnet.Network)
	}
	return fmt.Sprintf("%s(%s)\\nnetworks[%s]", *segment.DisplayName, *segment.Type, strings.Join(nAddresses, ","))
}
