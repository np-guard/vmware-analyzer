package common

import "fmt"

// this file contains enumerated values for various flags options

const (
	enumFlagType = "string"
	errPrefix    = "must be one of %s"
)

// ///////////////////////////////////////////////////////////////////////////////////////////
// outFormat is a custom flag type.
// Cobra allows to define custom value types to be used as flags through the pflag.(*FlagSet).Var() method.
// defining a new type that implements the pflag.Value interface.
type OutFormat string

const (
	// out format values
	TextFormat OutFormat = "txt"
	DotFormat  OutFormat = "dot"
	JSONFormat OutFormat = "json"
	SVGFormat  OutFormat = "svg"
)

var allFormats = []*OutFormat{
	PointerTo(TextFormat),
	PointerTo(DotFormat),
	PointerTo(JSONFormat),
	PointerTo(SVGFormat),
}
var AllFormatsStr = JoinStringifiedSlice(allFormats, CommaSeparator)

// String is used both by fmt.Print and by Cobra in help text
func (e *OutFormat) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *OutFormat) Set(v string) error {
	switch v {
	case string(TextFormat), string(DotFormat), string(JSONFormat), string(SVGFormat):
		*e = OutFormat(v)
		return nil
	default:
		return fmt.Errorf(errPrefix, AllFormatsStr)
	}
}

// Type is only used in help text
func (e *OutFormat) Type() string {
	return enumFlagType
}

func (e *OutFormat) SetDefault() {
	*e = TextFormat
}

/////////////////////////////////////////////////////////////////////////////////////////////

type Endpoints string

const (
	// target endpoints for migration config values
	EndpointsVMs  Endpoints = "vms"
	EndpointsPods Endpoints = "pods"
	EndpointsBoth Endpoints = "both"
)

var allEndpoints = []*Endpoints{
	PointerTo(EndpointsVMs),
	PointerTo(EndpointsPods),
	PointerTo(EndpointsBoth),
}
var AllEndpointsStr = JoinStringifiedSlice(allEndpoints, CommaSeparator)

func (e *Endpoints) String() string {
	return string(*e)
}

func (e *Endpoints) Set(v string) error {
	switch v {
	case string(EndpointsVMs), string(EndpointsPods), string(EndpointsBoth):
		*e = Endpoints(v)
		return nil
	default:
		return fmt.Errorf(errPrefix, AllEndpointsStr)
	}
}

func (e *Endpoints) Type() string {
	return enumFlagType
}

func (e *Endpoints) SetDefault() {
	*e = EndpointsBoth
}

/////////////////////////////////////////////////////////////////////////////////////////////

type Segments string

const (
	// target options for segments migration values
	SegmentsToPodNetwork Segments = "pod-network"
	SegmentsToUDNs       Segments = "udns"
)

var allSegmentOptions = []*Segments{
	PointerTo(SegmentsToPodNetwork),
	PointerTo(SegmentsToUDNs),
}
var AllSegmentOptionsStr = JoinStringifiedSlice(allSegmentOptions, CommaSeparator)

func (e *Segments) String() string {
	return string(*e)
}

func (e *Segments) Set(v string) error {
	switch v {
	case string(SegmentsToPodNetwork), string(SegmentsToUDNs):
		*e = Segments(v)
		return nil
	default:
		return fmt.Errorf(errPrefix, AllSegmentOptionsStr)
	}
}

func (e *Segments) Type() string {
	return enumFlagType
}

func (e *Segments) SetDefault() {
	*e = SegmentsToUDNs
}

/////////////////////////////////////////////////////////////////////////////////////////////

type LogLevel string

const (
	LogLevelFatal  LogLevel = "fatal"
	LogLevelError  LogLevel = "error"
	LogLevelWarn   LogLevel = "warn"
	LogLevelInfo   LogLevel = "info"
	LogLevelDebug  LogLevel = "debug"
	LogLevelDebug2 LogLevel = "debug2" // more debug messages than "debug" level
)

var allLogLevelOptions = []*LogLevel{
	PointerTo(LogLevelFatal),
	PointerTo(LogLevelError),
	PointerTo(LogLevelWarn),
	PointerTo(LogLevelInfo),
	PointerTo(LogLevelDebug),
	PointerTo(LogLevelDebug2),
}
var AllLogLevelOptionsStr = JoinStringifiedSlice(allLogLevelOptions, CommaSeparator)

func (e *LogLevel) String() string {
	return string(*e)
}

func (e *LogLevel) Set(v string) error {
	switch v {
	case string(LogLevelFatal), string(LogLevelError), string(LogLevelWarn),
		string(LogLevelInfo), string(LogLevelDebug), string(LogLevelDebug2):
		*e = LogLevel(v)
		return nil
	default:
		return fmt.Errorf(errPrefix, AllLogLevelOptionsStr)
	}
}

func (e *LogLevel) Type() string {
	return enumFlagType
}

func (e *LogLevel) SetDefault() {
	*e = LogLevelFatal // quiet mode by default
}
