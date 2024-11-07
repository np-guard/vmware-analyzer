/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"fmt"
	"path"
	"reflect"
	"unsafe"
)

// /////////////////////////////////////////////////////////////////////////////////

type iteratorUser interface{}
type atStructFunc func(user interface{}, structInstance interface{})
type filterFunc func(user interface{}, structInstance interface{}) bool

func iterate(root interface{}, user iteratorUser, atStruct atStructFunc, filter filterFunc) {
	iter := basicIterator{
		atStruct: atStruct,
		filter:   filter,
		user:     user,
	}
	iter.iterateValue(reflect.ValueOf(root))
}

type basicIterator struct {
	atStruct atStructFunc
	filter   filterFunc
	user     iteratorUser
}

func (iter *basicIterator) iterateValue(val reflect.Value) {
	switch val.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !val.IsNil() {
			iter.iterateValue(val.Elem())
		}
	case reflect.Slice:
		for j := 0; j < val.Len(); j++ {
			e := val.Index(j)
			iter.iterateValue(e)
		}
	case reflect.Struct:
		if iter.filter == nil || iter.filter(iter.user, val.Addr().Interface()) {
			iter.atStruct(iter.user, val.Addr().Interface())
		}
		for i := 0; i < val.NumField(); i++ {
			f := val.Field(i)
			iter.iterateValue(f)
		}
	case reflect.String, reflect.Bool, reflect.Int:
	default:
		fmt.Printf("fail to parse %v\n", val.Kind().String())
		return
	}
}

//////////////////////////////////////////////////////////////////////////////////////

func instancePointer(structInstance interface{}) unsafe.Pointer {
	v := reflect.ValueOf(structInstance)
	return v.UnsafePointer()
}

func structName(structInstance interface{}) string {
	return reflect.TypeOf(structInstance).Elem().Name()
}
func pkgName(structInstance interface{}) string {
	return path.Base(reflect.TypeOf(structInstance).Elem().PkgPath())
}
func getField(structInstance interface{}, fieldName string) (string, bool) {
	f := reflect.ValueOf(structInstance).Elem().FieldByName(fieldName)
	if f.IsValid() && !f.IsNil() {
		return f.Elem().String(), true
	}
	return "", false
}
func setField(structInstance interface{}, fieldName, value string) {
	reflect.ValueOf(structInstance).Elem().FieldByName(fieldName).Elem().SetString(value)
}
func clearField(structInstance interface{}, fieldName string) {
	f := reflect.ValueOf(structInstance).Elem().FieldByName(fieldName)
	if f.IsValid() && !f.IsNil() {
		f.SetZero()
	}
}

func getSliceLen(structInstance interface{}, fieldName string) int {
	f := reflect.ValueOf(structInstance).Elem().FieldByName(fieldName)
	if f.IsValid() && !f.IsNil() {
		return f.Len()
	}
	return 0
}

func getSliceField(structInstance interface{}, fieldName string, index int) (string, bool) {
	f := reflect.ValueOf(structInstance).Elem().FieldByName(fieldName)
	if f.IsValid() && !f.IsNil() {
		return f.Index(index).String(), true
	}
	return "", false
}
func setSliceField(structInstance interface{}, fieldName, value string, index int) {
	reflect.ValueOf(structInstance).Elem().FieldByName(fieldName).Index(index).SetString(value)
}
