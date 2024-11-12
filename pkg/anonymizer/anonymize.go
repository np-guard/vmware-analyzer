/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anonymizer

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	// "github.com/np-guard/vmware-analyzer/pkg/logging"
)

// anonymize() is top function of the anonymization algorithm.
// the anonymization is calling the iterate() function several time to do the anonymization.

func anonymize(st structInstance, anonInstruction *anonInstruction) error {
	anonymizer := newAnonymizer(anonInstruction)
	if err := iterate(st, anonymizer, collectIDsToKeep, toAnonymizeFilter); err != nil {
		return err
	}
	if err := iterate(st, anonymizer, anonymizeIDs, toAnonymizeFilter); err != nil {
		return err
	}
	if err := iterate(st, anonymizer, anonymizeIDRefs, toAnonymizeFilter); err != nil {
		return err
	}
	if err := iterate(st, anonymizer, collectPaths, toAnonymizeFilter); err != nil {
		return err
	}
	if err := anonymizer.anonymizeAllPaths(); err != nil {
		return err
	}
	if err := iterate(st, anonymizer, anonymizePaths, toAnonymizeFilter); err != nil {
		return err
	}
	if err := iterate(st, anonymizer, anonymizeFields, toAnonymizeFilter); err != nil {
		return err
	}
	// logging.Debugf("anonymization statistics:\n%s\n", anonymizer.statistics.string())
	err:=common.WriteToFile("anon.txt", anonymizer.statistics.string())
	if err != nil {
		fmt.Println(err.Error())
	}

	return nil
}

func toAnonymizeFilter(user iteratorUser, structInstance structInstance) bool {
	return user.(*anonymizer).toAnonymizeFilter(structInstance)
}
func collectIDsToKeep(user iteratorUser, structInstance structInstance) error {
	return user.(*anonymizer).collectIDsToKeep(structInstance)
}
func anonymizeIDs(user iteratorUser, structInstance structInstance) error {
	return user.(*anonymizer).anonymizeIDs(structInstance)
}
func anonymizeIDRefs(user iteratorUser, structInstance structInstance) error {
	return user.(*anonymizer).anonymizeIDRefs(structInstance)
}
func anonymizeFields(user iteratorUser, structInstance structInstance) error {
	return user.(*anonymizer).anonymizeFields(structInstance)
}
func collectPaths(user iteratorUser, structInstance structInstance) error {
	return user.(*anonymizer).collectPaths(structInstance)
}
func anonymizePaths(user iteratorUser, structInstance structInstance) error {
	return user.(*anonymizer).anonymizePaths(structInstance)
}
