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

type iteratorUser interface{}
type atStructFunc func(user iteratorUser, structInstance structInstance)
type filterFunc func(user iteratorUser, structInstance structInstance) bool

func iterate(root structInstance, user iteratorUser, atStruct atStructFunc, filter filterFunc) error{
	iter := basicIterator{
		atStruct: atStruct,
		filter:   filter,
		user:     user,
	}
	return iter.iterateValue(reflect.ValueOf(root))
}

type basicIterator struct {
	atStruct atStructFunc
	filter   filterFunc
	user     iteratorUser
}

func (iter *basicIterator) iterateValue(val reflect.Value) error{
	switch val.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !val.IsNil() {
			return iter.iterateValue(val.Elem())
		}
	case reflect.Slice:
		for j := 0; j < val.Len(); j++ {
			e := val.Index(j)
			if err := iter.iterateValue(e); err != nil{
				return err
			}
		}
	case reflect.Struct:
		if iter.filter == nil || iter.filter(iter.user, val.Addr().Interface()) {
			iter.atStruct(iter.user, val.Addr().Interface())
		}
		for i := 0; i < val.NumField(); i++ {
			f := val.Field(i)
			if err := iter.iterateValue(f); err != nil{
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
