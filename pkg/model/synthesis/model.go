package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

type AbstractModelSyn struct {
	segments Segments
	tags     Tags // todo: should be computed by the collector or here?
	vms      VMs
	atomics  Atomics          // todo: should be used and maintained by FwRule
	rules    []*symbolicRules // with default deny
}

// Virtual machines' labels used in Atomic, e.g. tag = "backend"
// the following are used by NSX: Tag, Segment, (VM) Name, OS_Name, Computer_Name
// implemented by collector.Segment, endpoints.vm, Tag
// todo: Support OSName and ComputerName at POC?
type vmLabel interface {
	Name() string
}

// Tag a tag used by VMs for labeling in NSX
// todo: move to collector?
type Tag struct {
	name    string
	tagOrig resources.Tag
}

func (tag *Tag) Name() string {
	return tag.name
}

// Atomic -> label equal const_string, not Atomic
// represent a simple condition used for defining a group:
// tag/segment/name(/computer_Name/OS_Name?) equal/not equal string
type Atomic struct {
	label   vmLabel
	equalTo string
	neg     bool
}

func (*Atomic) string() string {
	return "" // todo: implement
}

// Clause a CNF Clause of Atomics
type Clause []*Atomic

// maps used by AbstractModelSyn

// Segments topology; map from segment name to the segment
type Segments map[string]*collector.Segment

// Tags map from tag's name to the tag
type Tags map[string]*Tag

// VMs map from VM name to the VM
type VMs map[string]*endpoints.VM

// Atomics map from Atomics's string to *Atomic
type Atomics map[string]*Atomic

// ToDo: when we simplify CNFExpr, clauses will be translated to map[string]int

type CNFExpr []Clause

// SymbolicPaths all path from a src VM satisfying src to dst VM satisfying dst
type SymbolicPaths struct {
	src CNFExpr
	dst CNFExpr
}

// RuleForSynthesis input to synthesis. Synthesis very likely to non-prioritized only allow rules
type RuleForSynthesis struct {
	dfw.FwRule
	actualSymbolicRule []SymbolicPaths // paths enabled by this rule
}

// todo: will have to combine different categories into a single list of inbound, outbound
type symbolicRules struct {
	inbound  []*RuleForSynthesis // ordered list inbound RuleForSynthesis
	outbound []*RuleForSynthesis // ordered list outbound RuleForSynthesis
}
