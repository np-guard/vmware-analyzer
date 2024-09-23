/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"os"
	"path"
)
const (
	writeFileMode = 0o600
)
func WriteToFile(file, content string) error {
	err := os.MkdirAll(path.Dir(file), os.ModePerm)
	if err != nil {
		return err
	}
	return os.WriteFile(file, []byte(content), writeFileMode)
}
