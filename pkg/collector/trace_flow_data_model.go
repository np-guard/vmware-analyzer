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
	SourceID *string `json:"source_id,omitempty"`
}

func (config *TraceflowConfig) UnmarshalJSON(b []byte) error {
	return UnmarshalBaseStructAndFields(b, nilWithType, "packet", &config.Packet, "source_id", &config.SourceID)
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

func toRawMap(tf TraceFlowObservationElement) (map[string]json.RawMessage, error) {
	b, err := json.Marshal(tf)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	err = json.Unmarshal(b, &raw)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func getRule(tf TraceFlowObservationElement) (string, error) {
	raw, err := toRawMap(tf)
	if err != nil {
		return "", err
	}
	return string(raw["acl_rule_id"]), nil
}

func isLastObservation(tf TraceFlowObservationElement) bool {
	raw, err := toRawMap(tf)
	if err != nil {
		return false
	}
	eType := string(raw["resource_type"])
	return strings.Contains(eType, "Dropped") || strings.Contains(eType, "Delivered")
}

//////////////////////////////////////////////////////////

type TraceFlowObservations []TraceFlowObservationElement

func (tfs TraceFlowObservations) completed() bool {
	return len(tfs) > 0 && isLastObservation(tfs[len(tfs)-1])
}
func (tfs TraceFlowObservations) isDelivered() bool {
	if len(tfs) == 0 {
		return false
	}
	lastObservation := tfs[len(tfs)-1]
	raw, err := toRawMap(lastObservation)
	if err != nil {
		return false
	}
	eType := string(raw["resource_type"])
	return strings.Contains(eType, "Delivered")
}

type traceflowResult struct {
	Delivered bool   `json:"delivered"`
	SrcRuleID string `json:"src_rule_id,omitempty"`
	DstRuleID string `json:"dst_rule_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (tfs TraceFlowObservations) results() traceflowResult {
	res := traceflowResult{}
	if !tfs.completed() {
		res.Error = "traceflow is not completed"
	} else {
		res.Delivered = tfs.isDelivered()
	}
	for _, tf := range tfs {
		ruleId, err := getRule(tf)
		switch {
		case err != nil:
			res.Error = err.Error()
			return res
		case ruleId == "":
		case res.SrcRuleID == "":
			res.SrcRuleID = ruleId
		case res.DstRuleID == "":
			res.DstRuleID = ruleId
		default:
			res.Error = "got three rules in one traceflow"
			return res
		}
	}
	if res.DstRuleID == "" && res.Delivered {
		res.Error = "traceflow was delivered without destination rule"

	}
	return res
}

//nolint:funlen,gocyclo // just a long function
func (tfs *TraceFlowObservations) UnmarshalJSON(b []byte) error {
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return err
	}
	*tfs = make([]TraceFlowObservationElement, len(raws))
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
		(*tfs)[i] = res
	}
	return nil
}
