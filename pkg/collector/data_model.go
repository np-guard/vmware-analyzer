/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"encoding/json"

)

// Helper function for unmarshalling

func jsonToMap(jsonStr []byte) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	err := json.Unmarshal(jsonStr, &result)
	return result, err
}

func basicUnmarshal[A any](data []byte, unmarshalFunc func(map[string]json.RawMessage, any) error,
	objRef *A, tags *BaseTaggedResource) error {
	asMap, err := jsonToMap(data)
	if err != nil {
		return err
	}

	asRef := new(A)
	err = unmarshalFunc(asMap, &asRef)
	if err != nil {
		return err
	}
	*objRef = *asRef

	if tags != nil {
		err = json.Unmarshal(data, tags)
		if err != nil {
			return err
		}
	}

	return nil
}

// The following types define the "canonical data model" for IBM resources.
// For the most part, these are the SDK types extended with extra information like tags or info from multiple calls

type TaggedResource interface {
	SetTags([]string)
	GetCRN() *string
}

// BaseTaggedResource type is used as an abstraction for all resources that IBM allows tagging
type BaseTaggedResource struct {
	Tags []string `json:"tags"`
}

func (res *BaseTaggedResource) SetTags(tags []string) {
	res.Tags = tags
}

