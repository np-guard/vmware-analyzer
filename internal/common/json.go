package common

import "encoding/json"

func MarshalJSON(v any) (string, error) {
	res, err := json.MarshalIndent(v, "", "    ")
	return string(res), err
}
