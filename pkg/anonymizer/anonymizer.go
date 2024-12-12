/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// the anonymization:
// * each instance of a struct has a uniq number.
// * there are three kind of fields, IDs, Paths and regular fields
// * here some anonymization types by examples, all at the form:
//     <struct name>.<field>                     = <new anon value>:
// 1.  Service.Id                                = DCM_Java_Object_Cache_port
// 2.  Service.UniqId                            = "Service.UniqueId:10010"
// 3.  Service.RealizationId                     = "Service.UniqueId:10010"
// 4.  VirtualMachine.ExternalId                 = "VirtualMachine.ExternalId:10784"
// 5.  VirtualMachine.DisplayName                = "VirtualMachine.DisplayName:10784"
// 6.  RealizedVirtualMachine.DisplayName        = "VirtualMachine.DisplayName:10784"
// 7.  RealizedVirtualMachine.Id                 = "VirtualMachine.ExternalId:10784"
// 8.  VirtualNetworkInterface.OwnerVmId         = "VirtualMachine.ExternalId:10784"
// 9.  IpAddressInfo.IpAddresses                 = "IpAddressInfo.IpAddresses:10932.0"
// 10. IpAddressInfo.IpAddresses                 = ""192.168.1.2""
// 11. SegmentPort.Path                          = "/infra/segments/Segment.Id:10833/ports/SegmentPort.Id:10834"
// 12. SegmentPort.RemotePath                    = nil
// 13. FirewallRule.Sources[0].TargetId          = "Group.UniqueId:10884"
// 14. FirewallRule.Sources[0].TargetDisplayName = "Group.DisplayName:10884"
// 15. Service.DisplayName                       = "AD Server"

// all these examples are different cases of anonymization, the anonymizer follow the anonInstruction struct.
// the field in anonInstruction:
// pkgsToSkip             - packages that it ignores (we ignores the collector pkg, )
// structsToSkip          - structs that it skip (for "abstract" structs )
// idFields               - fields that we anonymize using the instance number (see examples 2,4 )
// idsToKeep              - ids that we do not anonymize (see example 1)
// idRefFields            - ids that we update according to ids that we already anonymized (see example 3,7,8)
// refStructs             - some structs are reference to another structs,
//                          so we take the instance number from the referred structs (see example 7)
// fields                 - fields that are not ids, we anonymize using the instance number (see example 5)
// fieldsByCondition      - fields that are not ids, we anonymize only if it satisfy a condition function (see examples 9,10)
// slicesByCondition      - same, but for slices
// fieldsByRef            - fields that are not ids, we anonymize using the instance number of another instance, according to a given Id.
//                          (see example 14, according to example 13)
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
	structsNotToSkip       []string
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
	pathSliceFields        []string
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
type statistic struct {
	oldVal, newVal string
}
type statistics map[statistic]int

func (s statistics) addStatistic(oldVal, newVal string) {
	s[statistic{oldVal, newVal}]++
}

func (s statistics) string() string {
	res := ""
	keys := slices.Collect(maps.Keys(s))
	slices.SortFunc(keys, func(s1, s2 statistic) int { return strings.Compare(s1.oldVal, s2.oldVal) })
	for i, k := range keys {
		if i > 0 && keys[i-1].oldVal == k.oldVal {
			res += "Warning- Duplication: "
		}
		res += fmt.Sprintf("%s\t:%s\t %d\n", k.oldVal, k.newVal, s[k])
	}
	return res
}

type anonymizer struct {
	instancesNumber       map[pointer]int        // the uniq anon number of each instance
	numberToInstance      map[int]structInstance // uniq anon number the instance
	instanceNumberCounter int                    // the counter, to create a new anonymization
	oldToAnonsInfo        map[string]*anonInfo   // map from old value to anon info
	newToAnonsInfo        map[string]*anonInfo   // map from new value to anon info
	paths                 []string               // all the orig paths
	anonymizedPaths       map[string]string      // map from orig to anon path
	anonInstruction       *anonInstruction       // the instruction to anon with
	statistics            statistics
}

func newAnonymizer() *anonymizer {
	return &anonymizer{
		instanceNumberCounter: firstAnonNumber,
		instancesNumber:       map[pointer]int{},
		numberToInstance:      map[int]structInstance{},
		oldToAnonsInfo:        map[string]*anonInfo{},
		newToAnonsInfo:        map[string]*anonInfo{},
		anonymizedPaths:       map[string]string{},
		statistics:            statistics{},
	}
}
func (a *anonymizer) setAnonInstruction(anonInstruction *anonInstruction) {
	a.anonInstruction = anonInstruction
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
	a.numberToInstance[number] = structInstance
}

func (a *anonymizer) toAnonymizeFilter(structInstance structInstance) bool {
	if a.anonInstruction.structsNotToSkip != nil && slices.Contains(a.anonInstruction.structsNotToSkip, pkgName(structInstance)) {
		return true
	}
	if slices.Contains(a.anonInstruction.pkgsToSkip, pkgName(structInstance)) {
		return false
	}
	if slices.Contains(a.anonInstruction.structsToSkip, structName(structInstance)) {
		return false
	}
	return true
}
func (a *anonymizer) setField(structInstance structInstance, fieldName, oldValue, value string) {
	a.statistics.addStatistic(oldValue, value)
	setField(structInstance, fieldName, value)
}

///////////////////////////////////////////////////////////////////////////////////////

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

func (a *anonymizer) anonymizeIDRefs(structInstance structInstance) error {
	for _, f := range a.anonInstruction.idRefFields {
		if err := a.anonymizeIDRef(structInstance, f); err != nil {
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
	return nil
}

func (a *anonymizer) anonymizeFieldsByRef(structInstance structInstance) error {
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
	for _, fieldName := range a.anonInstruction.pathSliceFields {
		for i := 0; i < getSliceLen(structInstance, fieldName); i++ {
			oldVal, ok := getSliceField(structInstance, fieldName, i)
			if ok {
				a.paths = append(a.paths, oldVal)
			}
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
			return fmt.Errorf("error - did not find anonymise path of %s for field %s", oldVal, fieldName)
		}
		a.setField(structInstance, fieldName, oldVal, anonVal)
	}
	for _, fieldName := range a.anonInstruction.pathSliceFields {
		for i := 0; i < getSliceLen(structInstance, fieldName); i++ {
			oldVal, ok := getSliceField(structInstance, fieldName, i)
			if !ok {
				continue
			}
			anonVal, ok := a.anonymizedPaths[oldVal]
			if !ok {
				return fmt.Errorf("error - did not find anonymise path of %s for field entry %s[%d]", oldVal, fieldName, i)
			}
			setSliceField(structInstance, fieldName, anonVal, i)
		}
	}
	return nil
}
