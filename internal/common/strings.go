package common

import (
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"
)

const (
	OutputSectionSep = "\n-------------------------------------------------------------------\n"
	ShortSep         = "\n-------------------------\n"

	CommaSeparator      string = ","
	CommaSpaceSeparator string = ", "
	NewLine             string = "\n"
	Tab                 string = "\t"
	carriageReturn      string = "\r"
	Space                      = " "

	AnalyzedConnectivityHeader = "Analyzed connectivity:"

	AnyStr = "ANY" // ANY can specify any service or any src/dst in DFW rules

	// ANSI escape codes - for colored output printed to the terminal
	reset   = "\033[0m"
	red     = "\033[31m"
	yellow  = "\033[33m"
	green   = "\033[32m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	gray    = "\033[37m"
	white   = "\033[97m"
)

// CleanStr for comparison that should be insensitive to line comparators; cleaning strings from line comparators
func CleanStr(str string) string {
	return strings.ReplaceAll(strings.ReplaceAll(str, NewLine, ""), carriageReturn, "")
}

type HasString interface {
	String() string
}

func JoinNonNilStrings(ptrSlice []*string, sep string) string {
	return JoinNonNil(ptrSlice, func(s *string) string { return *s }, sep)
}

func JoinNonNil[S any](ptrSlice []*S, f func(s *S) string, sep string) string {
	ptrSlice = slices.DeleteFunc(ptrSlice, func(s *S) bool { return s == nil })
	return JoinCustomStrFuncSlice(ptrSlice, f, sep)
}

func JoinNonEmpty(slice []string, sep string) string {
	slice = slices.DeleteFunc(slice, func(s string) bool { return s == "" })
	return strings.Join(slice, sep)
}

func CustomStrSliceToStrings[S any](slice []S, f func(s S) string) []string {
	resStrSlice := make([]string, len(slice))
	for i := range slice {
		resStrSlice[i] = f(slice[i])
	}
	// remove empty strings from the result
	resStrSlice = slices.DeleteFunc(resStrSlice, func(s string) bool { return s == "" })
	return resStrSlice
}

func CustomStrsSliceToStrings[S any](slice []S, f func(s S) []string) []string {
	resStrSlice := []string{}
	for _, e := range slice {
		resStrSlice = append(resStrSlice, f(e)...)
	}
	// remove empty strings from the result
	resStrSlice = slices.DeleteFunc(resStrSlice, func(s string) bool { return s == "" })
	return SliceCompact(resStrSlice)
}

func StringifiedSliceToStrings[S HasString](slice []S) []string {
	if slice == nil {
		return []string{}
	}
	return CustomStrSliceToStrings(slice, func(s S) string { return s.String() })
}

func JoinStringifiedSlice[S HasString](slice []S, separator string) string {
	resStrSlice := StringifiedSliceToStrings(slice)
	return strings.Join(resStrSlice, separator)
}

func SortedJoinStringifiedSlice[S HasString](slice []S, separator string) string {
	resStrSlice := StringifiedSliceToStrings(slice)
	slices.Sort(resStrSlice)
	return strings.Join(resStrSlice, separator)
}

func JoinCustomStrFuncSlice[S any](slice []S, f func(s S) string, separator string) string {
	resStrSlice := CustomStrSliceToStrings(slice, f)
	return strings.Join(resStrSlice, separator)
}

func SortedJoinCustomStrFuncSlice[S any](slice []S, f func(s S) string, separator string) string {
	resStrSlice := CustomStrSliceToStrings(slice, f)
	slices.Sort(resStrSlice)
	return strings.Join(resStrSlice, separator)
}

type TableOptions struct {
	Colors    bool
	SortLines bool
}

// GenerateTableString returns a string in table format for input header and lines
func GenerateTableString(header []string, lines [][]string, opts *TableOptions) string {
	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 1, 1, 1, ' ', tabwriter.Debug)
	lineFunc := func(s []string) string { return strings.Join(s, Tab) }

	if opts != nil && opts.Colors {
		editLinesWithColor(header, lines)
	}

	fmt.Fprintln(writer, lineFunc(header))
	if opts != nil && opts.SortLines {
		fmt.Fprintln(writer, SortedJoinCustomStrFuncSlice(lines, lineFunc, NewLine))
	} else {
		fmt.Fprintln(writer, JoinCustomStrFuncSlice(lines, lineFunc, NewLine))
	}

	fmt.Fprintln(writer, "")
	writer.Flush()
	return builder.String()
}

func editLinesWithColor(header []string, lines [][]string) {
	editLineWithColor(header, red)
	for i := range lines {
		editLineWithColor(lines[i], yellow)
	}
}

func editLineWithColor(line []string, color string) {
	maxInd := len(line) - 1
	if maxInd < 0 {
		return
	}
	line[0] = color + line[0]
	line[maxInd] += reset
}
