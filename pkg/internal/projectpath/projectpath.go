/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package projectpath

import (
	"path"
	"runtime"
)

const dirLevelUp = ".."

var (
	_, b, _, _ = runtime.Caller(0)

	// Root folder of this project
	// Root = path.Join(path.Dir(b), dirLevelUp, dirLevelUp, dirLevelUp)
	Root = path.Join(".", dirLevelUp, dirLevelUp, dirLevelUp)
)
