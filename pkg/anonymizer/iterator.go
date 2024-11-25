/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"fmt"
	"reflect"
)

// /////////////////////////////////////////////////////////////////////////////////
// iterate() is iterating over a tree data structure, recursively.
// for each struct, if the user supplied filter filterFunc() is satisfied, it call the user supplied function atStructFunc()
// these two function also get as a parameter the user of the iterator.

type iteratorUser interface{}
type atStructFunc func(user iteratorUser, structInstance structInstance) error
type filterFunc func(user iteratorUser, structInstance structInstance) bool

func iterate(root structInstance, user iteratorUser, atStruct atStructFunc, filter filterFunc) error {
	return iterateValue(reflect.ValueOf(root), user, atStruct, filter)
}

// the recursive function:
func iterateValue(val reflect.Value, user iteratorUser, atStruct atStructFunc, filter filterFunc) error {
	switch val.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !val.IsNil() {
			return iterateValue(val.Elem(), user, atStruct, filter)
		}
	case reflect.Slice:
		for j := 0; j < val.Len(); j++ {
			e := val.Index(j)
			if err := iterateValue(e, user, atStruct, filter); err != nil {
				return err
			}
		}
	case reflect.Struct:
		if filter == nil || filter(user, val.Addr().Interface()) {
			if err := atStruct(user, val.Addr().Interface()); err != nil {
				return err
			}
		}
		for i := 0; i < val.NumField(); i++ {
			f := val.Field(i)
			if err := iterateValue(f, user, atStruct, filter); err != nil {
				return err
			}
		}
	case reflect.String, reflect.Bool, reflect.Int:
	default:
		return fmt.Errorf("parsing %v is not supported", val.Kind().String())
	}
	return nil
}

//////////////////////////////////////////////////////////////////////////////////////
