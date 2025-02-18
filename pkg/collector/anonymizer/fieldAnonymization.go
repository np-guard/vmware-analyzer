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

func (a *anonymizer) anonymizeID(structInstance structInstance, fieldName string) error {
	oldVal, ok := getField(structInstance, fieldName)
	if !ok {
		return nil
	}
	structName := structName(structInstance)
	pkgName := pkgName(structInstance)
	if anonInfo, ok := a.oldToAnonsInfo[oldVal]; ok {
		switch {
		case oldVal == anonInfo.newValue:
		case structName == anonInfo.structName, a.anonInstruction.refStructs[structName] == anonInfo.structName:
			a.setInstanceNumber(structInstance, anonInfo.instanceNumber)
			a.setField(structInstance, fieldName, oldVal, a.oldToAnonsInfo[oldVal].newValue)
		default:
			return fmt.Errorf("error: id of field %s.%s.%s already anonymise by %s.%s.%s(%s)",
				pkgName, structName, fieldName,
				anonInfo.structPackage, anonInfo.structName, anonInfo.field,
				oldVal)
		}
		return nil
	}
	instanceNumber := a.instanceNumber(structInstance)
	newValue := a.anonVal(structName, fieldName, instanceNumber)
	a.addAnon(oldVal, newValue, pkgName, structName, fieldName, instanceNumber)
	a.setField(structInstance, fieldName, oldVal, newValue)
	return nil
}

func (a *anonymizer) anonymizeIDRef(structInstance structInstance, fieldName string) error {
	oldVal, ok := getField(structInstance, fieldName)
	if !ok {
		return nil
	}
	if _, ok = a.oldToAnonsInfo[oldVal]; !ok {
		if !slices.Contains(a.anonInstruction.idToCreateIfNotFound, fieldName) {
			return fmt.Errorf("id ref of field %s is not anonymized (%s)", fieldName, oldVal)
		}
		instanceNumber := a.instanceNumberCounter
		a.instanceNumberCounter++
		a.addAnon(oldVal, fmt.Sprintf("missing%s:%d", fieldName, instanceNumber), "", "missing", "", instanceNumber)
	}
	a.setField(structInstance, fieldName, oldVal, a.oldToAnonsInfo[oldVal].newValue)
	return nil
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
	a.setField(structInstance, fieldName, oldVal, v)
}

func (a *anonymizer) anonymizeSliceFieldFunc(structInstance structInstance, fieldName string, index int, filterFunc func(string) bool) {
	oldVal, ok := getSliceField(structInstance, fieldName, index)
	if !ok || oldVal == "" || (filterFunc != nil && !filterFunc(oldVal)) {
		return
	}
	v := fmt.Sprintf("%s.%s:%d.%d", structName(structInstance), fieldName, a.instanceNumber(structInstance), index)
	setSliceField(structInstance, fieldName, v, index)
}

func (a *anonymizer) anonymizeFieldByRef(structInstance structInstance, fs byRefField) error {
	oldVal, ok := getField(structInstance, fs.fieldName)
	if !ok || oldVal == "" {
		return nil
	}
	oldRefVal, ok := getField(structInstance, fs.refIDName)
	if !ok || oldVal == "" {
		return fmt.Errorf("id ref of field %s has no ref at %s", fs.fieldName, fs.refIDName)
	}
	refNumber := a.newToAnonsInfo[oldRefVal].instanceNumber
	refInstance := a.numberToInstance[refNumber]
	var newVal string
	if refInstance == nil {
		newVal = a.anonVal(a.newToAnonsInfo[oldRefVal].structName, fs.refName, a.newToAnonsInfo[oldRefVal].instanceNumber)
	} else {
		newVal, ok = getField(refInstance, fs.refName)
		if !ok || newVal == "" {
			return fmt.Errorf("struct %s has no val at field %s needed for %s.%s",
				a.newToAnonsInfo[oldRefVal].structName, fs.refName, structName(structInstance), fs.fieldName)
		}
	}
	a.setField(structInstance, fs.fieldName, oldVal, newVal)
	return nil
}

func (a *anonymizer) anonVal(sName, fieldName string, number int) string {
	if refName, ok := a.anonInstruction.refStructs[sName]; ok {
		sName = refName
	}
	return fmt.Sprintf("%s.%s:%d", sName, fieldName, number)
}

func (a *anonymizer) anonymizeAllPaths() error {
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
		if err := a.anonymizePath(p); err != nil {
			return err
		}
	}
	return nil
}

func (a *anonymizer) anonymizePath(p string) error {
	parent, id := path.Dir(p), path.Base(p)
	if _, ok := a.oldToAnonsInfo[id]; !ok {
		return fmt.Errorf("error - did not find anon Id %s from path %s", id, p)
	}
	parent, title := path.Dir(parent), path.Base(parent)
	if _, ok := a.anonymizedPaths[parent]; !ok {
		return fmt.Errorf("error - did not find parent path of %s", p)
	}
	a.anonymizedPaths[p] = path.Join(a.anonymizedPaths[parent], title, a.oldToAnonsInfo[id].newValue)
	return nil
}
