package cli

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

// outFormat is a custom flag type.
// Cobra allows to define custom value types to be used as flags through the pflag.(*FlagSet).Var() method.
// defining a new type that implements the pflag.Value interface.
type outFormat string

var (
	outFormatText outFormat = common.TextFormat
	outFormatDot  outFormat = common.DotFormat
	outFormatSvg  outFormat = common.SvgFormat
	outFormatJSON outFormat = common.JSONFormat
)

var allFormats = []*outFormat{&outFormatText, &outFormatDot, &outFormatSvg, &outFormatJSON}
var allFormatsStr = common.JoinStringifiedSlice(allFormats, common.CommaSeparator)

// String is used both by fmt.Print and by Cobra in help text
func (e *outFormat) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *outFormat) Set(v string) error {
	switch v {
	case common.TextFormat, common.DotFormat, common.JSONFormat, common.SvgFormat:
		*e = outFormat(v)
		return nil
	default:
		return fmt.Errorf("must be one of %s", allFormatsStr)
	}
}

// Type is only used in help text
func (e *outFormat) Type() string {
	return "string"
}
