package model

import (
	"fmt"
	"testing"
)

func TestParser(t *testing.T) {
	parser, err := NewNSXConfigParserFromFile("../../docs/simple2.json")
	if err != nil {
		t.Fatalf(err.Error())
	}

	err = parser.RunParser()
	if err != nil {
		t.Fatalf(err.Error())
	}
	config := parser.GetConfig()
	fmt.Println(config.getConfigInfoStr())

	config.ComputeConnectivity()
	fmt.Println("analyzed Connectivity")
	fmt.Println(config.analyzedConnectivity.String())
	fmt.Println("done")
}
