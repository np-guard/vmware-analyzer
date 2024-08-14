package model

import "github.com/np-guard/vmware-analyzer/pkg/model/endpoints"

// simple set of VMs for basic test
var vmA = endpoints.NewVM("A")
var vmB = endpoints.NewVM("B")
var vmC = endpoints.NewVM("C")
var allVms = []*endpoints.VM{vmA, vmB, vmC}
