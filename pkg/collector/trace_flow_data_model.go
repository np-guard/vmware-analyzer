/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"
	"fmt"
	"maps"
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

type TraceFlowObservationElement interface {
	Name() string
	Kind() string
}

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

func commonString(tf TraceFlowObservationElement) string {
	b, _ := json.Marshal(tf)
	var raw map[string]json.RawMessage
	json.Unmarshal(b, &raw)
	maps.DeleteFunc(raw, func(k string, v json.RawMessage) bool {
		//return (strings.Contains(k, "_id") && !strings.Contains(k, "rule")) ||
		return strings.Contains(k, "timestamp") || k == "sequence_no" ||
			(k == "component_sub_type" && string(v) == "UNKNOWN") || k == "resource_type"
	})
	toPrint, _ := json.MarshalIndent(raw, "", "    ")
	return string(toPrint)
}

func (tf *PolicyTraceflowObservationDelivered) Kind() string {
	return string(tf.ResourceType)
}
func (tf *PolicyTraceflowObservationDropped) Kind() string {
	return string(tf.ResourceType)
}
func (tf *PolicyTraceflowObservationDroppedLogical) Kind() string {
	return string(tf.ResourceType)
}
func (tf *PolicyTraceflowObservationForwardedLogical) Kind() string {
	return string(tf.ResourceType)
}
func (tf *PolicyTraceflowObservationReceivedLogical) Kind() string {
	return string(tf.ResourceType)
}
func (tf *PolicyTraceflowObservationRelayedLogical) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationDelivered) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationDropped) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationDroppedLogical) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationForwarded) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationForwardedLogical) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationProtected) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationReceived) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationReceivedLogical) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationRelayedLogical) Kind() string {
	return string(tf.ResourceType)
}
func (tf *TraceflowObservationReplicationLogical) Kind() string {
	return string(tf.ResourceType)
}

func (tf *PolicyTraceflowObservationDelivered) Name() string {
	return commonString(tf)
}
func (tf *PolicyTraceflowObservationDropped) Name() string {
	return commonString(tf)
}
func (tf *PolicyTraceflowObservationDroppedLogical) Name() string {
	return commonString(tf)
}
func (tf *PolicyTraceflowObservationForwardedLogical) Name() string {
	return commonString(tf)
}
func (tf *PolicyTraceflowObservationReceivedLogical) Name() string {
	return commonString(tf)
}
func (tf *PolicyTraceflowObservationRelayedLogical) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationDelivered) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationDropped) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationDroppedLogical) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationForwarded) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationForwardedLogical) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationProtected) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationReceived) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationReceivedLogical) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationRelayedLogical) Name() string {
	return commonString(tf)
}
func (tf *TraceflowObservationReplicationLogical) Name() string {
	return commonString(tf)
}


type observationNode struct {
	ip        string
	vmName    string
	reason    string
	ruleId    string
	ruleName  string
	dropped   bool
	delivered bool
}

func (o *observationNode) Kind() string {
	if o.ip != "" {
		return "src/dst"
	}
	return "observation"
}
func (o *observationNode) Name() string {
	res := ""
	if o.ip != "" {
		res += fmt.Sprintf("%s[%s]\n", o.vmName, o.ip)
	}
	if o.dropped {
		res += fmt.Sprintf("dropped because %s\n", o.reason)
	}
	if o.ruleId != "" {
		res += fmt.Sprintf("rule id %s[%s]\n", o.ruleId, o.ruleName)
	}
	return res
}
func createObservationNode(tf TraceFlowObservationElement) *observationNode {
	res := observationNode{}
	b, _ := json.Marshal(tf)
	var raw map[string]json.RawMessage
	json.Unmarshal(b, &raw)
	eType := string(raw["resource_type"])
	res.dropped = strings.Contains(eType, "Dropped")
	res.delivered = strings.Contains(eType, "Delivered")
	res.ruleId = string(raw["acl_rule_id"])
	empty := observationNode{}
	if res == empty {
		return nil
	}
	return &res
}

//////////////////////////////////////////////////////////

type TraceFlowObservations []TraceFlowObservationElement

func (tfs TraceFlowObservations) observationNodes() []*observationNode {
	res := []*observationNode{}
	for _, tf := range tfs {
		if o := createObservationNode(tf); o != nil {
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
