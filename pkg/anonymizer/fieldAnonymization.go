/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////

func (a *anonymizer) anonymizeID(structInstance structInstance, fieldName string) {
	oldVal, ok := getField(structInstance, fieldName)
	if !ok {
		return
	}
	structName := structName(structInstance)
	pkgName := pkgName(structInstance)
	if anonInfo, ok := a.oldToAnonsInfo[oldVal]; ok {
		switch {
		case oldVal == anonInfo.newValue:
		case structName == anonInfo.structName, a.anonInstruction.refStructs[structName] == anonInfo.structName:
			a.setInstanceNumber(structInstance, anonInfo.instanceNumber)
			setField(structInstance, fieldName, a.oldToAnonsInfo[oldVal].newValue)
		default:
			fmt.Printf("error: id of field %s.%s.%s already anonymise by %s.%s.%s(%s)\n",
				pkgName, structName, fieldName,
				anonInfo.structPackage, anonInfo.structName, anonInfo.field,
				oldVal)
		}
		return
	}
	instanceNumber := a.instanceNumber(structInstance)
	newValue := a.anonVal(structName, fieldName, instanceNumber)
	a.addAnon(oldVal, newValue, pkgName, structName, fieldName, instanceNumber)
	setField(structInstance, fieldName, newValue)
}

func (a *anonymizer) anonymizeRef(structInstance structInstance, fieldName string) {
	oldVal, ok := getField(structInstance, fieldName)
	if !ok {
		return
	}
	if _, ok = a.oldToAnonsInfo[oldVal]; !ok {
		fmt.Printf("id ref of field %s is not anonymise (%s)\n", fieldName, oldVal)
		instanceNumber := a.instanceNumberCounter
		a.instanceNumberCounter++
		a.addAnon(oldVal, fmt.Sprintf("missing:%d", instanceNumber), "", "missing", "", instanceNumber)
	}
	setField(structInstance, fieldName, a.oldToAnonsInfo[oldVal].newValue)
}

func (a *anonymizer) anonymizeField(structInstance structInstance, fieldName string) {
	a.anonymizeFieldFunc(structInstance, fieldName, nil)
}

func (a *anonymizer) anonymizeFieldFunc(structInstance structInstance, fieldName string, filterFunc func(string) bool) {
	oldVal, ok := getField(structInstance, fieldName)
	if !ok || oldVal == "" || (filterFunc != nil && !filterFunc(oldVal)) {
		return
	}
	v := a.anonVal(structName(structInstance), fieldName, a.instanceNumber(structInstance))
	setField(structInstance, fieldName, v)
}

func (a *anonymizer) anonymizeSliceFieldFunc(structInstance structInstance, fieldName string, index int, filterFunc func(string) bool) {
	oldVal, ok := getSliceField(structInstance, fieldName, index)
	if !ok || oldVal == "" || (filterFunc != nil && !filterFunc(oldVal)) {
		return
	}
	v := fmt.Sprintf("%s.%s:%d.%d", structName(structInstance), fieldName, a.instanceNumber(structInstance), index)
	setSliceField(structInstance, fieldName, v, index)
}

func (a *anonymizer) anonymizeFieldByRef(structInstance structInstance, fieldName, refIDName, refName string) {
	oldVal, ok := getField(structInstance, fieldName)
	if !ok || oldVal == "" {
		return
	}
	oldRefVal, ok := getField(structInstance, refIDName)
	if !ok || oldVal == "" {
		fmt.Printf("id ref of field %s has no ref at %s\n", fieldName, refIDName)
		return
	}
	v := a.anonVal(a.newToAnonsInfo[oldRefVal].structName, refName, a.newToAnonsInfo[oldRefVal].instanceNumber)
	setField(structInstance, fieldName, v)
}

func (a *anonymizer)anonVal(sName, fieldName string, number int) string {
	if refName, ok := a.anonInstruction.refStructs[sName]; ok {
		sName = refName
	}
	return fmt.Sprintf("%s.%s:%d", sName, fieldName, number)
}

func (a *anonymizer) anonymizeAllPaths() {
	slices.SortFunc(a.paths, func(p1, p2 string) int {
		a := strings.Count(p1, "/") - strings.Count(p2, "/")
		if a != 0 {
			return a
		}
		return strings.Compare(p1, p2)
	})
	a.paths = slices.Compact(a.paths)

	a.paths = slices.DeleteFunc(a.paths, func(p string) bool { return slices.Contains(a.anonInstruction.rootPaths, p) })
	for _, p := range a.anonInstruction.rootPaths {
		a.anonymizedPaths[p] = p
	}
	for _, p := range a.paths {
		a.anonymizePath(p)
	}
}

func (a *anonymizer) anonymizePath(p string) {
	parent, id := path.Dir(p), path.Base(p)
	if _, ok := a.oldToAnonsInfo[id]; !ok {
		fmt.Printf("error - did not find anon Id %s from path %s\n", id, p)
		a.anonymizedPaths[p] = p
		return
	}
	parent, title := path.Dir(parent), path.Base(parent)
	if _, ok := a.anonymizedPaths[parent]; !ok {
		fmt.Printf("error - did not find parent path of %s\n", p)
		a.anonymizedPaths[parent] = parent
	}
	a.anonymizedPaths[p] = path.Join(a.anonymizedPaths[parent], title, a.oldToAnonsInfo[id].newValue)
}
