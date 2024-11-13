package model

import (
	"fmt"
	"testing"
)

func TestParser(t *testing.T) {
	parser, err := NewNSXConfigParserFromFile("../../examples/anonymized_example.json") // simple7
	if err != nil {
		t.Fatal(err.Error())
	}

	err = parser.RunParser()
	if err != nil {
		t.Fatal(err.Error())
	}
	config := parser.GetConfig()
	fmt.Println(config.getConfigInfoStr())

	config.ComputeConnectivity()
	fmt.Println("analyzed Connectivity")
	fmt.Println(config.analyzedConnectivity.String())
	fmt.Println("done")
}
