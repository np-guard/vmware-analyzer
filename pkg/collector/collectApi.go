/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

const rateTimeLimit = 200 * time.Millisecond

func fixLowerCaseEnums(b []byte) []byte {
	enumVals := []nsx.RealizedVirtualMachinePowerState{
		nsx.RealizedVirtualMachinePowerStateUNKNOWN,
		nsx.RealizedVirtualMachinePowerStateVMRUNNING,
		nsx.RealizedVirtualMachinePowerStateVMSTOPPED,
		nsx.RealizedVirtualMachinePowerStateVMSUSPENDED,
	}
	for _, enumVal := range enumVals {
		rightCase, _ := json.Marshal(enumVal)
		wrongCase := bytes.ToLower(rightCase)
		b = bytes.ReplaceAll(b, wrongCase, rightCase)
	}
	return b
}

func collectResult[A any](server ServerData, resourceQuery string, resource *A) error {
	b, err := curlGetRequest(server, resourceQuery)
	if err != nil {
		return err
	}
	b = fixLowerCaseEnums(b)
	res, err := unmarshalResults[A](b)
	if err != nil {
		return err
	}
	*resource = *res
	return nil
}

func collectResultList[A any](server ServerData, resourceQuery string, resourceList *[]A) error {
	var totalRes []A
	for cursor := ""; totalRes == nil || cursor != ""; {
		currentQuery := resourceQuery
		if cursor != "" {
			currentQuery = fmt.Sprintf("%s?cursor=%s", resourceQuery, cursor)
		}
		b, err := curlGetRequest(server, currentQuery)
		if err != nil {
			return err
		}
		b = fixLowerCaseEnums(b)
		var currentRes []A
		currentRes, cursor, err = unmarshalResultsToList[A](b)
		if err != nil {
			return err
		}
		totalRes = append(currentRes, totalRes...)
	}
	*resourceList = totalRes
	return nil
}

func collectResource[A json.Unmarshaler](server ServerData, resourceQuery string, resource A) error {
	b, err := curlGetRequest(server, resourceQuery)
	if err != nil {
		return err
	}
	err = (resource).UnmarshalJSON(b)
	if err != nil {
		return err
	}
	return nil
}

func PutResource[A json.Unmarshaler](server ServerData, query string, resource A) error {
	bs, err := curlPutRequest(server, query, resource)
	if err != nil {
		return err
	}
	err = (resource).UnmarshalJSON(bs)
	if err != nil {
		return err
	}
	err = checkForUnmarshalError(bs)
	if err != nil {
		return err
	}
	return nil
}
func DeleteResource(server ServerData, query string) error {
	_, err := curlDeleteRequest(server, query)
	return err
}

func curlGetRequest(server ServerData, query string) ([]byte, error) {
	return curlRequest(server, query, http.MethodGet, "", http.NoBody)
}
func curlDeleteRequest(server ServerData, query string) ([]byte, error) {
	return curlRequest(server, query, http.MethodDelete, "", http.NoBody)
}

func curlPutRequest(server ServerData, query string, data any) ([]byte, error) {
	bs, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	body := bytes.NewReader(bs)
	return curlRequest(server, query, http.MethodPut, "application/json", body)
}

func curlRequest(server ServerData, query, method, contentType string, body io.Reader) ([]byte, error) {
	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

	//nolint:gosec // need insecure TLS option for testing and development
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: server.insecureSkipVerify},
	}
	client := &http.Client{Transport: tr}

	//nolint:noctx // no context for testing and development
	req, err := http.NewRequest(method, server.host+"/"+query, body)
	logging.Infof("%s %s\n", method, query)
	if err != nil {
		return nil, err
	}
	if server.user != "" {
		req.SetBasicAuth(server.user, server.password)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	time.Sleep(rateTimeLimit)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func unmarshalResultsToList[A any](b []byte) (res []A, cursor string, err error) {
	data := struct {
		Results *[]A
		Cursor  string
	}{}
	err = json.Unmarshal(b, &data)
	if err != nil {
		return nil, "", err
	}
	if data.Results == nil {
		return nil, "", getUnmarshalError(b)
	}
	return *data.Results, data.Cursor, nil
}

func unmarshalResults[A any](b []byte) (*A, error) {
	data := struct{ Results *A }{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}
	if data.Results == nil {
		return nil, getUnmarshalError(b)
	}
	return data.Results, nil
}

type nestedError struct {
	ErrorMessage  string        `json:"error_message"`
	ErrorCode     int           `json:"error_code"`
	RelatedErrors []nestedError `json:"related_errors"`
}

func getUnmarshalError(b []byte) error {
	apiErrors, err := TryUnmarshalError(b)
	if err != nil {
		return err
	}
	return errors.New(strings.Join(apiErrors, "\n"))
}
func checkForUnmarshalError(b []byte) error {
	apiErrors, err := TryUnmarshalError(b)
	if err != nil {
		return nil //nolint:nilerr // there is no error in the code
	}
	return errors.New(strings.Join(apiErrors, "\n"))
}

func TryUnmarshalError(b []byte) ([]string, error) {
	errorData := nestedError{}
	err := json.Unmarshal(b, &errorData)
	if err != nil {
		return nil, err
	}
	if errorData.ErrorCode != 0 || errorData.ErrorMessage != "" {
		eStrings := []string{fmt.Sprintf("api error %d: %s", errorData.ErrorCode, errorData.ErrorMessage)}
		for _, e := range errorData.RelatedErrors {
			eStrings = append(eStrings, fmt.Sprintf("related error %d: %s", e.ErrorCode, e.ErrorMessage))
		}
		return eStrings, nil
	}
	return nil, fmt.Errorf("fail to unmarshal %s", string(b))
}
