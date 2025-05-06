/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	writeFileMode = 0o600
)

func WriteToFile(file, content string) error {
	err := os.MkdirAll(filepath.Dir(file), os.ModePerm)
	if err != nil {
		return err
	}
	return os.WriteFile(file, []byte(content), writeFileMode)
}

func FileExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func WriteYamlUsingJSON[A any](content []A, file string) error {
	outs := make([]string, len(content))
	for i := range content {
		buf, err := marshalYamlUsingJSON(content[i])
		if err != nil {
			return err
		}
		outs[i] = string(buf)
	}
	return WriteToFile(file, strings.Join(outs, "---\n"))
}

func marshalYamlUsingJSON(content interface{}) ([]byte, error) {
	// Directly marshaling content into YAML, results in malformed Kubernetes resources.
	// This is because K8s NetworkPolicy struct has json field tags, but no yaml field tags (also true for other resources).
	// The (somewhat ugly) solution is to first marshal content to json, unmarshal to an interface{} var and marshal to yaml
	buf, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	var contentFromJSON interface{}
	err = json.Unmarshal(buf, &contentFromJSON)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(contentFromJSON)
}
