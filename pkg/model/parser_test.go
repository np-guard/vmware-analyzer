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

	err = parser.runParser()
	if err != nil {
		t.Fatalf(err.Error())
	}
	config := parser.getConfig()
	fmt.Println(config.getConfigInfoStr())

	config.computeConnectivity()
	fmt.Println("analyzed Connectivity")
	fmt.Println(config.analyzedConnectivity.string())
	fmt.Println("done")
}
