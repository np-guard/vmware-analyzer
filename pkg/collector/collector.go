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

func CollectResources(NSXServer, user_name, password string) (*ResourcesContainerModel, error) {
	c := curlData{NSXServer, user_name, password}
	res := NewResourcesContainerModel()
	err := collectResourceList(c, "api/v1/fabric/virtual-machines", &res.VirtualMachineList)
	if err != nil {
		return nil, err
	}
	domain, err := getDomain(c)
	err = collectResourceList(c, "policy/api/v1/infra/domains/"+domain+"/security-policies", &res.SecurityPolicyList)
	if err != nil {
		return nil, err
	}
	return res, nil
}

type curlData struct{
	NSXServer, user_name, password string
}

func getDomain(c curlData) (string, error){
	type domain struct{
		Id string
	}
	domains := []*domain{}
	err := collectResourceList(c, "policy/api/v1/infra/domains", &domains)
	if err != nil {
		return "", err
	}
	return domains[0].Id, nil
}

func collectResourceList[A any](c curlData, resource_key string, resouceList *[]*A) error {
	b, err := curlReq(c, resource_key)
	if err != nil {
		return err
	}
	*resouceList, err = unmarshalToList[A](b)
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

func curlReq(c curlData, key string) ([]byte, error) {
	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", c.NSXServer+"/"+key, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user_name, c.password)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
