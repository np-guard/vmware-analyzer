
/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"path"
	"reflect"
	"unsafe"
)
type structInstance interface{}
type pointer unsafe.Pointer

func instancePointer(structInstance structInstance) pointer {
	v := reflect.ValueOf(structInstance)
	return pointer(v.UnsafePointer())
}
func structName(structInstance structInstance) string {
	return reflect.TypeOf(structInstance).Elem().Name()
}
func pkgName(structInstance structInstance) string {
	return path.Base(reflect.TypeOf(structInstance).Elem().PkgPath())
}
func getField(structInstance structInstance, fieldName string) (string, bool) {
	f := reflect.ValueOf(structInstance).Elem().FieldByName(fieldName)
	if f.IsValid() && !f.IsNil() {
		return f.Elem().String(), true
	}
	return "", false
}
func setField(structInstance structInstance, fieldName, value string) {
	reflect.ValueOf(structInstance).Elem().FieldByName(fieldName).Elem().SetString(value)
}
func clearField(structInstance structInstance, fieldName string) {
	f := reflect.ValueOf(structInstance).Elem().FieldByName(fieldName)
	if f.IsValid() && !f.IsNil() {
		f.SetZero()
	}
}
func getSliceLen(structInstance structInstance, fieldName string) int {
	f := reflect.ValueOf(structInstance).Elem().FieldByName(fieldName)
	if f.IsValid() && !f.IsNil() {
		return f.Len()
	}
	return 0
}
func getSliceField(structInstance structInstance, fieldName string, index int) (string, bool) {
	f := reflect.ValueOf(structInstance).Elem().FieldByName(fieldName)
	if f.IsValid() && !f.IsNil() {
		return f.Index(index).String(), true
	}
	return "", false
}
func setSliceField(structInstance structInstance, fieldName, value string, index int) {
	reflect.ValueOf(structInstance).Elem().FieldByName(fieldName).Index(index).SetString(value)
}
