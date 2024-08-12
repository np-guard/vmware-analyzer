package nsx

import (
	"fmt"
	"testing"

	api "github.com/vmware/go-vmware-nsxt"
	manager "github.com/vmware/go-vmware-nsxt/manager"
	policy "github.com/vmware/go-vmware-nsxt/policy"
)

// experiment with types from the api
func TestBasic(t *testing.T) {
	config := &api.Configuration{}
	fmt.Printf("%v", config)
	fw := &policy.RealizedFirewall{}
	fwSection := &manager.FirewallSection{}
	svc := &manager.L4PortSetNsServiceEntry{}
	rule := &manager.FirewallRule{}
	gr := &manager.NsGroup{
		MembershipCriteria: []manager.NsGroupTagExpression{
			/*ResourceType: "Condition",*/
		},
	}
	fmt.Printf("%v", fwSection)
	fmt.Printf("%v", fw)
	fmt.Printf("%v", svc)
	fmt.Printf("%v", rule)
	fmt.Printf("%v", gr)
}
