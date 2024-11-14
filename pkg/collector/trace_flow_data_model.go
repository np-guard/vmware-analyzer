/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"fmt"
	"strings"

	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

// ///////////////////////////////////////////////////////////////////////////////////////
type TraceflowConfig struct {
	// Configuration of packet data
	Packet *nsx.FieldsPacketData `json:"packet,omitempty" yaml:"packet,omitempty" mapstructure:"packet,omitempty"`
	// Policy path or UUID (validated for syntax only) of segment port to start
	// traceflow from. Auto-plumbed ports don't have corresponding policy path. Both
	// overlay backed port and VLAN backed port are supported.
	SourceId *string `json:"source_id,omitempty" yaml:"source_id,omitempty" mapstructure:"source_id,omitempty"`
}

func (config *TraceflowConfig) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAndFields(b, nilWithType, "packet", &config.Packet, "source_id", &config.SourceId)
}

///////////////////////////////////////////////////////////////////////////////////////

type TraceFlowObservationElement interface{}

type PolicyTraceflowObservationDelivered struct {
	nsx.PolicyTraceflowObservationDelivered
}
type PolicyTraceflowObservationDropped struct {
	nsx.PolicyTraceflowObservationDropped
}
type PolicyTraceflowObservationDroppedLogical struct {
	nsx.PolicyTraceflowObservationDroppedLogical
}
type PolicyTraceflowObservationForwardedLogical struct {
	nsx.PolicyTraceflowObservationForwardedLogical
}
type PolicyTraceflowObservationReceivedLogical struct {
	nsx.PolicyTraceflowObservationReceivedLogical
}
type PolicyTraceflowObservationRelayedLogical struct {
	nsx.PolicyTraceflowObservationRelayedLogical
}
type TraceflowObservationDelivered struct {
	nsx.TraceflowObservationDelivered
}
type TraceflowObservationDropped struct {
	nsx.TraceflowObservationDropped
}
type TraceflowObservationDroppedLogical struct {
	nsx.TraceflowObservationDroppedLogical
}
type TraceflowObservationForwarded struct {
	nsx.TraceflowObservationForwarded
}
type TraceflowObservationForwardedLogical struct {
	nsx.TraceflowObservationForwardedLogical
}
type TraceflowObservationProtected struct {
	nsx.TraceflowObservationProtected
}
type TraceflowObservationReceived struct {
	nsx.TraceflowObservationReceived
}
type TraceflowObservationReceivedLogical struct {
	nsx.TraceflowObservationReceivedLogical
}
type TraceflowObservationRelayedLogical struct {
	nsx.TraceflowObservationRelayedLogical
}
type TraceflowObservationReplicationLogical struct {
	nsx.TraceflowObservationReplicationLogical
}

type observationNode struct {
	ip        string
	vmName    string
	reason    string
	rule      *FirewallRule
	dropped   bool
	delivered bool
}

func (o *observationNode) Kind() string {
	switch {
	case o.vmName != "":
		return "Virtual Machine"
	case o.ip != "":
		return "dst IP"
	}
	return "observation"
}

func (o *observationNode) Name() string {
	res := "\n"
	if o.ip != "" {
		res += fmt.Sprintf("%s[%s]\n", o.vmName, o.ip)
	}
	if o.dropped {
		res += fmt.Sprintf("dropped here, because %s\n", o.reason)
	}
	if o.delivered {
		res += "delivered here\n"
	}
	if o.rule != nil {
		res += fmt.Sprintf("rule id %s[%s]\n", *o.rule.Id, *o.rule.DisplayName)
	}
	return res
}
func toObservationNode(tf TraceFlowObservationElement, resources *ResourcesContainerModel) *observationNode {
	res := observationNode{}
	b, _ := json.Marshal(tf)
	var raw map[string]json.RawMessage
	json.Unmarshal(b, &raw)
	eType := string(raw["resource_type"])
	res.dropped = strings.Contains(eType, "Dropped")
	res.delivered = strings.Contains(eType, "Delivered")
	ruleId := string(raw["acl_rule_id"])
	if ruleId != "" {
		res.rule = resources.GetRule(ruleId)
	}
	res.reason = string(raw["reason"])
	empty := observationNode{}
	if res == empty {
		return nil
	}
	return &res
}

func isLastObservation(tf TraceFlowObservationElement) bool {
	b, _ := json.Marshal(tf)
	var raw map[string]json.RawMessage
	json.Unmarshal(b, &raw)
	eType := string(raw["resource_type"])
	return strings.Contains(eType, "Dropped") || strings.Contains(eType, "Delivered")
}

//////////////////////////////////////////////////////////

type TraceFlowObservations []TraceFlowObservationElement

func (tfs TraceFlowObservations) completed() bool {
	return len(tfs) > 0 && isLastObservation(tfs[len(tfs)-1])
}

func (tfs TraceFlowObservations) observationNodes(resources *ResourcesContainerModel) []*observationNode {
	res := []*observationNode{}
	for _, tf := range tfs {
		if o := toObservationNode(tf, resources); o != nil {
			res = append(res, o)
		}
	}
	return res
}

func (e *TraceFlowObservations) UnmarshalJSON(b []byte) error {
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return err
	}
	*e = make([]TraceFlowObservationElement, len(raws))
	for i, rawMessage := range raws {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rawMessage, &raw); err != nil {
			return err
		}
		var cType string
		if err := json.Unmarshal(raw[resourceTypeJSONEntry], &cType); err != nil {
			return err
		}
		var res TraceFlowObservationElement
		switch cType {
		case "PolicyTraceflowObservationDelivered":
			res = &PolicyTraceflowObservationDelivered{}
		case "PolicyTraceflowObservationDropped":
			res = &PolicyTraceflowObservationDropped{}
		case "PolicyTraceflowObservationDroppedLogical":
			res = &PolicyTraceflowObservationDroppedLogical{}
		case "PolicyTraceflowObservationForwardedLogical":
			res = &PolicyTraceflowObservationForwardedLogical{}
		case "PolicyTraceflowObservationReceivedLogical":
			res = &PolicyTraceflowObservationReceivedLogical{}
		case "PolicyTraceflowObservationRelayedLogical":
			res = &PolicyTraceflowObservationRelayedLogical{}
		case "TraceflowObservationDelivered":
			res = &TraceflowObservationDelivered{}
		case "TraceflowObservationDropped":
			res = &TraceflowObservationDropped{}
		case "TraceflowObservationDroppedLogical":
			res = &TraceflowObservationDroppedLogical{}
		case "TraceflowObservationForwarded":
			res = &TraceflowObservationForwarded{}
		case "TraceflowObservationForwardedLogical":
			res = &TraceflowObservationForwardedLogical{}
		case "TraceflowObservationProtected":
			res = &TraceflowObservationProtected{}
		case "TraceflowObservationReceived":
			res = &TraceflowObservationReceived{}
		case "TraceflowObservationReceivedLogical":
			res = &TraceflowObservationReceivedLogical{}
		case "TraceflowObservationRelayedLogical":
			res = &TraceflowObservationRelayedLogical{}
		case "TraceflowObservationReplicationLogical":
			res = &TraceflowObservationReplicationLogical{}
		default:
			return fmt.Errorf("fail to unmarshal TraceFlowObservations %s", rawMessage)
		}
		if err := json.Unmarshal(rawMessage, &res); err != nil {
			return err
		}
		(*e)[i] = res
	}
	return nil
}
