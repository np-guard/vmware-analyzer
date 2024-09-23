/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

func fixLowerCaseEnums(b []byte) []byte {
	enimVals := []resources.RealizedVirtualMachinePowerState{
		resources.RealizedVirtualMachinePowerStateUNKNOWN,
		resources.RealizedVirtualMachinePowerStateVMRUNNING,
		resources.RealizedVirtualMachinePowerStateVMSTOPPED,
		resources.RealizedVirtualMachinePowerStateVMSUSPENDED,
	}
	for _, emunVal := range enimVals {
		wrongCase := fmt.Sprintf("\"%s\"", strings.ToLower(string(emunVal)))
		rightCase := fmt.Sprintf("\"%s\"", string(emunVal))
		b = bytes.Replace(b, []byte(wrongCase), []byte(rightCase), -1)
	}
	return b
}

func collectResultList[A any](server serverData, resourceQuery string, resouceList *[]A) error {
	bytes, err := curlRequest(server, resourceQuery)
	if err != nil {
		return err
	}
	bytes = fixLowerCaseEnums(bytes)
	*resouceList, err = unmarshalResultsToList[A](bytes)
	if err != nil {
		return err
	}
	return nil
}

func collectResource[A json.Unmarshaler](server serverData, resourceQuery string, resource A) error {
	bytes, err := curlRequest(server, resourceQuery)
	if err != nil {
		return err
	}
	err = (resource).UnmarshalJSON(bytes)
	if err != nil {
		return err
	}
	return nil
}

func curlRequest(server serverData, query string) ([]byte, error) {
	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

	//nolint:gosec // need insecure TLS option for testing and development
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	//nolint:noctx // no context for testing and development
	req, err := http.NewRequest(http.MethodGet, server.nsxServer+"/"+query, http.NoBody)
	if err != nil {
		return nil, err
	}
	if server.userName != "" {
		req.SetBasicAuth(server.userName, server.password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func unmarshalResultsToList[A any](b []byte) ([]A, error) {
	data := struct{ Results *[]A }{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}
	if data.Results == nil {
		return nil, getUnmarshalError(b)
	}
	return *data.Results, nil
}

func getUnmarshalError(b []byte) error {
	errorData := struct {
		ErrorMessage string  `json:"error_message"`
		ErrorCode    int `json:"error_code"`
	}{}
	err := json.Unmarshal(b, &errorData)
	if err != nil {
		return err
	}
	if errorData.ErrorCode != 0 || errorData.ErrorMessage != "" {
		return fmt.Errorf("http error %d: %s", errorData.ErrorCode, errorData.ErrorMessage)
	}
	return fmt.Errorf("fail to unmarshal %s", b)
}
