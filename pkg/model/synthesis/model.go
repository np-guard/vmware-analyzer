package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
)

// todo to "VM struct" by collector the following
// todo 1. Tag
// todo 2. Segment
// todo 3. VMName
// todo: add OSName and ComputerName as well?
// todo add to dfw.FwRule symbolicAllowPaths

type abstractModelSyn struct {
	segments Segments
	rules    []*abstractRules // with default deny
}

// Segments topology; map from segment name to the segment
type Segments map[string]*collector.Segment

// Virtual machines' labels used in atomic, e.g. tag = "backend"
// the following are used by NSX: Tag, Segment, (VM) Name, OS_Name, Computer_Name
// todo: these should be collected by the collector. Will we support all?
type vmLabel interface {
	Name() string
}

// Tag todo: move the following to collector or to some other place?
type Tag struct {
	name string
	// todo: anything else?
}

type VMName struct {
	name string
	// todo: anything else?
}

// Tags map from tag's name to the tag
type Tags map[string]*Tag

// VMNames map from VMName name to the tag
type VMNames map[string]*VMName

func (tag *Tag) Name() string {
	return tag.name
}

func (vmName *VMName) Name() string {
	return vmName.name
}

// atomic -> label equal const_string, not atomic
type atomic struct {
	label   vmLabel
	equalTo string
	neg     bool
}

func (*atomic) string() string {
	return ""
}

// map atomic's string to atomic
type atomics map[string]*atomic

// a CNF clause of atomics
type clause []string

// ToDo: when we simplify CNFExpr, clauses will be translated to map[string]int

type CNFExpr []clause

// symbolicAllowPaths: all path from a src VM satisfying src to dst VM satisfying dst
type symbolicAllowPaths struct {
	src CNFExpr
	dst CNFExpr
}

// RuleForSynthesis input to synthesis. Synthesis very likely to non-prioritized only allow rules
type RuleForSynthesis struct {
	dfw.FwRule
	symbolicRule []symbolicAllowPaths // paths enabled by this rule
}

// todo: will have to combine different categories into a single list of inbound, outbound
type abstractRules struct {
	inbound  []*RuleForSynthesis // ordered list inbound RuleForSynthesis
	outbound []*RuleForSynthesis // ordered list outbound RuleForSynthesis
}
