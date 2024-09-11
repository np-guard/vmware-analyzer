/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package collector

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
)

func collectResourceList[A any](server serverData, resourceQuary string, resouceList *[]*A) error {
	bytes, err := curlReq(server, resourceQuary)
	if err != nil {
		return err
	}
	*resouceList, err = unmarshalToList[A](bytes)
	if err != nil {
		return err
	}
	return nil
}

func unmarshalToList[A any](b []byte) ([]*A, error) {
	data := struct{ Results []*A }{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}
	return data.Results, nil
}

func curlReq(server serverData, quary string) ([]byte, error) {
	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", server.NSXServer+"/"+quary, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(server.user_name, server.password)

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
