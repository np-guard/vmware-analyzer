package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
)

type SynthesisOptions struct {
	Hints                   *symbolicexpr.Hints
	InferHints              bool
	SynthesizeAdmin         bool
	Color                   bool
	CreateDNSPolicy         bool
	FilterVMs               []string
	EndpointsMapping        common.Endpoints
	SegmentsMapping         common.Segments
	PolicyOptimizationLevel common.PolicyOptimizationLevel
	// TargetNamespace, when set, is the default Kubernetes namespace for all NSX segments
	// (single-project / global collapse). Per-segment SegmentNamespaceMap entries override it.
	TargetNamespace string
	// SegmentNamespaceMap maps NSX segment display names to target Kubernetes namespace names.
	// When unset/empty (and TargetNamespace is also unset), each segment becomes a namespace
	// named ToLegalK8SString(segment.Name). Multiple segments may map to the same namespace.
	SegmentNamespaceMap map[string]string
}

func (options *SynthesisOptions) OutputOption() *common.OutputParameters {
	return &common.OutputParameters{Color: options.Color, VMs: options.FilterVMs}
}

// LoadSegmentNamespaceMapFile reads a YAML or JSON object mapping segment names to namespaces.
// Keys are NSX segment display names (as used in the abstract model). Values are Kubernetes namespace names.
func LoadSegmentNamespaceMapFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading segment-namespace map file %q: %w", path, err)
	}
	m := map[string]string{}
	if err := yaml.Unmarshal(b, &m); err != nil {
		// YAML also parses most JSON objects; try strict JSON for a clearer error on failure.
		if jerr := json.Unmarshal(b, &m); jerr != nil {
			return nil, fmt.Errorf("parsing segment-namespace map file %q as YAML/JSON: %w", path, err)
		}
	}
	if err := validateSegmentNamespaceMap(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ParseSegmentNamespaceMapCSV parses "Seg-Web=tom-testing,Seg-Database=tom-testing".
func ParseSegmentNamespaceMapCSV(s string) (map[string]string, error) {
	m := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return m, nil
	}
	for _, part := range strings.Split(s, common.CommaSeparator) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid segment-namespace map entry %q; expected SegmentName=namespace", part)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" || v == "" {
			return nil, fmt.Errorf("invalid segment-namespace map entry %q; empty key or value", part)
		}
		m[k] = v
	}
	if err := validateSegmentNamespaceMap(m); err != nil {
		return nil, err
	}
	return m, nil
}

func validateSegmentNamespaceMap(m map[string]string) error {
	for k, v := range m {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("segment-namespace map contains empty key or value")
		}
	}
	return nil
}

// MergeSegmentNamespaceMaps returns a copy of base with overrides applied.
func MergeSegmentNamespaceMaps(base, overrides map[string]string) map[string]string {
	if len(base) == 0 && len(overrides) == 0 {
		return nil
	}
	res := map[string]string{}
	for k, v := range base {
		res[k] = v
	}
	for k, v := range overrides {
		res[k] = v
	}
	return res
}
