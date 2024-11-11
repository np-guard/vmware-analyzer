/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"fmt"
	"slices"
)

const firstAnonNumber = 10000

type conditionField struct {
	fieldName string
	filter    func(string) bool
}
type anonInstruction struct {
	theReferenceField string
	pkgsToSkip        []string
	structsToSkip     []string
	refStructs        map[string]string
	structsToNotAnon  []string
	idFields          []string
	idRefFields       []string
	fields            []string
	fieldsByCondition []conditionField
	slicesByCondition []conditionField
	fieldsByRef       [][]string
	fieldsToClear     []string
	pathFields        []string
	pathToCleanFields []string
	rootPaths         []string
}

type anonInfo struct {
	newValue       string
	oldValue       string
	structPackage  string
	structName     string
	field          string
	instanceNumber int
}
type anonymizer struct {
	instancesNumber       map[pointer]int
	instanceNumberCounter int
	oldToAnonsInfo        map[string]*anonInfo
	newToAnonsInfo        map[string]*anonInfo
	paths                 []string
	anonymizedPaths       map[string]string
	anonInstruction       *anonInstruction
}

func newAnonymizer(anonInstruction *anonInstruction) *anonymizer {
	return &anonymizer{
		instanceNumberCounter: firstAnonNumber,
		instancesNumber:       map[pointer]int{},
		oldToAnonsInfo:        map[string]*anonInfo{},
		newToAnonsInfo:        map[string]*anonInfo{},
		anonymizedPaths:       map[string]string{},
		anonInstruction:       anonInstruction,
	}
}

func (a *anonymizer) addAnon(oldVal, newVal string,
	structPackage, structName, field string,
	instancesNumber int) {
	anon := &anonInfo{
		oldValue:       oldVal,
		newValue:       newVal,
		structPackage:  structPackage,
		structName:     structName,
		field:          field,
		instanceNumber: instancesNumber,
	}
	a.newToAnonsInfo[newVal] = anon
	a.oldToAnonsInfo[oldVal] = anon
}

func (a *anonymizer) instanceNumber(structInstance structInstance) int {
	p := instancePointer(structInstance)
	if _, ok := a.instancesNumber[p]; !ok {
		a.setInstanceNumber(structInstance, a.instanceNumberCounter)
		a.instanceNumberCounter++
	}
	return a.instancesNumber[p]
}

func (a *anonymizer) setInstanceNumber(structInstance structInstance, number int) {
	p := instancePointer(structInstance)
	a.instancesNumber[p] = number
}

func (a *anonymizer) toAnonymizeFilter(structInstance structInstance) bool {
	if slices.Contains(a.anonInstruction.pkgsToSkip, pkgName(structInstance)) {
		return false
	}
	if slices.Contains(a.anonInstruction.structsToSkip, structName(structInstance)) {
		return false
	}
	return true
}

func (a *anonymizer) collectIDsToKeep(structInstance structInstance) {
	structName := structName(structInstance)
	pkgName := pkgName(structInstance)
	if !slices.Contains(a.anonInstruction.structsToNotAnon, structName) {
		return
	}
	id, ok := getField(structInstance, a.anonInstruction.theReferenceField)
	if !ok {
		fmt.Printf("%s has no %s\n", structName, a.anonInstruction.theReferenceField)
	} else {
		a.addAnon(id, id, pkgName, structName, a.anonInstruction.theReferenceField, 0)
	}
}

func (a *anonymizer) anonymizeIDs(structInstance structInstance) {
	for _, f := range a.anonInstruction.idFields {
		a.anonymizeID(structInstance, f)
	}
}

func (a *anonymizer) anonymizeRefs(structInstance structInstance) {
	for _, f := range a.anonInstruction.idRefFields {
		a.anonymizeRef(structInstance, f)
	}
}

func (a *anonymizer) anonymizeFields(structInstance structInstance) {
	structName := structName(structInstance)
	if slices.Contains(a.anonInstruction.structsToNotAnon, structName) {
		return
	}
	for _, f := range a.anonInstruction.fields {
		a.anonymizeField(structInstance, f)
	}
	for _, f := range a.anonInstruction.slicesByCondition {
		for i := 0; i < getSliceLen(structInstance, f.fieldName); i++ {
			a.anonymizeSliceFieldFunc(structInstance, f.fieldName, i, f.filter)
		}
	}
	for _, f := range a.anonInstruction.fieldsByCondition {
		a.anonymizeFieldFunc(structInstance, f.fieldName, f.filter)
	}

	for _, fs := range a.anonInstruction.fieldsByRef {
		a.anonymizeFieldByRef(structInstance, fs[0], fs[1], fs[2])
	}
	for _, f := range append(a.anonInstruction.fieldsToClear, a.anonInstruction.pathToCleanFields...) {
		clearField(structInstance, f)
	}
}

func (a *anonymizer) collectPaths(structInstance structInstance) {
	for _, fieldName := range a.anonInstruction.pathFields {
		oldVal, ok := getField(structInstance, fieldName)
		if ok {
			a.paths = append(a.paths, oldVal)
		}
	}
}

func (a *anonymizer) anonymizePaths(structInstance structInstance) {
	for _, fieldName := range a.anonInstruction.pathFields {
		oldVal, ok := getField(structInstance, fieldName)
		if !ok {
			continue
		}
		anonVal, ok := a.anonymizedPaths[oldVal]
		if !ok {
			fmt.Printf("error - did not find anonymise path of %s\n", oldVal)
		} else {
			setField(structInstance, fieldName, anonVal)
		}
	}
}
