/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"fmt"
	"slices"
)

// the anonymization:
// each instance of a struct has a uniq number.
// anonymization types by examples,at the form:
//      <struct name>.<field>             = <new anon value>:
// 1.  Service.Id                         = DCM_Java_Object_Cache_port
// 2.  Service.UniqId                     = "Service.UniqueId:10010"
// 3.  Service.RealizationId              = "Service.UniqueId:10010"
// 4.  VirtualMachine.ExternalId          = "VirtualMachine.ExternalId:10784"
// 5.  VirtualMachine.DisplayName         = "VirtualMachine.DisplayName:10784"
// 6.  RealizedVirtualMachine.DisplayName = "VirtualMachine.DisplayName:10784"
// 7.  RealizedVirtualMachine.Id          = "VirtualMachine.ExternalId:10784"
// 8.  VirtualNetworkInterface.OwnerVmId  = "VirtualMachine.ExternalId:10784"
// 9.  IpAddressInfo.IpAddresses          = "IpAddressInfo.IpAddresses:10932.0"
// 10. IpAddressInfo.IpAddresses          = ""192.168.1.2""
// 11. SegmentPort.Path                   = "/infra/segments/Segment.Id:10833/ports/SegmentPort.Id:10834"
// 12. SegmentPort.RemotePath             = nil
// 13. FirewallRule.Sources[0].TargetId   = "Group.UniqueId:10884"
// 14. FirewallRule.Sources[0].TargetDisplayName = "Group.DisplayName:10884"
// 15. Service.DisplayName                = "AD Server"

// all these examples are different cases of anonymization, the anonymizer follow the anonInstruction struct.
// the field in anonInstruction:
// pkgsToSkip             - packages the it ignores (we ignores the collector pkg, )
// structsToSkip          - structs that it skip (for "abstract" structs )
// idFields               - fields that we anonymize using the instance number (see examples 2,4 )
// idsToKeep              - ids that we do not anonymize (see example 1)
// idRefFields            - ids that we update according to ids that we already anonymized (see example 3,7,8)
// refStructs             - some structs are reference to another structs,
//                          so we take the instance number from the referred structs (see example 7)
// fields                 - fields that are not ids, we anonymize using the instance number (see example 5)
// fieldsByCondition      - fields that are not ids, we anonymize only if it satisfy a condition function (see examples 9,10)
// slicesByCondition      - same, but for slices
// fieldsByRef            - fields that are not ids, we anonymize using the instance number of another instance, according to a given Id.(see example 14, according to example 13)
// structsToNotAnonFields - struct that we do not anonymize their fields(which are not Ids) ( see example 15)
// fieldsToClear          - field to delete the content (see example 12)
// pathFields             - paths to fix, according to the Ids ( see example 11)
// pathToCleanFields      - paths to delete the content (see example 12)
// rootPaths              - acceptable path prefixes

const firstAnonNumber = 10000

type byRefField struct {
	fieldName, refIDName, refName string
}
type conditionField struct {
	fieldName string
	filter    func(string) bool
}
type idToKeep struct {
	structName string
	fieldName  string
}

type anonInstruction struct {
	pkgsToSkip             []string
	structsToSkip          []string
	refStructs             map[string]string
	structsToNotAnonFields []string
	idFields               []string
	idsToKeep              []idToKeep
	idRefFields            []string
	fields                 []string
	fieldsByCondition      []conditionField
	slicesByCondition      []conditionField
	fieldsByRef            []byRefField
	fieldsToClear          []string
	idToCreateIfNotFound   []string
	pathFields             []string
	pathToCleanFields      []string
	rootPaths              []string
}

// anonInfo holds the info of one ID anonymization
type anonInfo struct {
	newValue       string
	oldValue       string
	structPackage  string
	structName     string
	field          string
	instanceNumber int
}

type anonymizer struct {
	instancesNumber       map[pointer]int      // the uniq anon number of each instance
	instanceNumberCounter int                  // the counter, to create a new anonymization
	oldToAnonsInfo        map[string]*anonInfo // map from old value to anon info
	newToAnonsInfo        map[string]*anonInfo // map from new value to anon info
	paths                 []string             // all the orig paths
	anonymizedPaths       map[string]string    // map from orig to anon path
	anonInstruction       *anonInstruction     // the instruction to anon with
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

func (a *anonymizer) collectIDsToKeep(structInstance structInstance) error {
	structName := structName(structInstance)
	ids := slices.DeleteFunc(slices.Clone(a.anonInstruction.idsToKeep), func(f idToKeep) bool { return f.structName != structName })
	pkgName := pkgName(structInstance)
	for _, f := range ids {
		if id, ok := getField(structInstance, f.fieldName); ok {
			a.addAnon(id, id, pkgName, structName, f.fieldName, 0)
		}
	}
	return nil
}

func (a *anonymizer) anonymizeIDs(structInstance structInstance) error {
	for _, f := range a.anonInstruction.idFields {
		if err := a.anonymizeID(structInstance, f); err != nil {
			return err
		}
	}
	return nil
}

func (a *anonymizer) anonymizeIdRefs(structInstance structInstance) error {
	for _, f := range a.anonInstruction.idRefFields {
		if err := a.anonymizeIdRef(structInstance, f); err != nil {
			return err
		}
	}
	return nil
}

func (a *anonymizer) anonymizeFields(structInstance structInstance) error {
	structName := structName(structInstance)
	for _, f := range append(a.anonInstruction.fieldsToClear, a.anonInstruction.pathToCleanFields...) {
		clearField(structInstance, f)
	}
	if slices.Contains(a.anonInstruction.structsToNotAnonFields, structName) {
		return nil
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
		if err := a.anonymizeFieldByRef(structInstance, fs); err != nil {
			return err
		}
	}
	return nil
}

func (a *anonymizer) collectPaths(structInstance structInstance) error {
	for _, fieldName := range a.anonInstruction.pathFields {
		oldVal, ok := getField(structInstance, fieldName)
		if ok {
			a.paths = append(a.paths, oldVal)
		}
	}
	return nil
}

func (a *anonymizer) anonymizePaths(structInstance structInstance) error {
	for _, fieldName := range a.anonInstruction.pathFields {
		oldVal, ok := getField(structInstance, fieldName)
		if !ok {
			continue
		}
		anonVal, ok := a.anonymizedPaths[oldVal]
		if !ok {
			return fmt.Errorf("error - did not find anonymise path of %s", oldVal)
		} else {
			setField(structInstance, fieldName, anonVal)
		}
	}
	return nil
}
