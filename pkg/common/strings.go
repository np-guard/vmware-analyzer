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

type HasString interface {
	String() string
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

func stringifiedSliceToStrings[S HasString](slice []S) []string {
	return CustomStrSliceToStrings(slice, func(s S) string { return s.String() })
}

func JoinStringifiedSlice[S HasString](slice []S, separator string) string {
	resStrSlice := stringifiedSliceToStrings(slice)
	return strings.Join(resStrSlice, separator)
}

func SortedJoinStringifiedSlice[S HasString](slice []S, separator string) string {
	resStrSlice := stringifiedSliceToStrings(slice)
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

// GenerateTableString returns a string in table format for input header and lines
func GenerateTableString(header []string, lines [][]string) string {
	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 1, 1, 1, ' ', tabwriter.Debug)
	fmt.Fprintln(writer, strings.Join(header, Tab))
	for _, line := range lines {
		fmt.Fprintln(writer, strings.Join(line, Tab))
	}
	writer.Flush()
	return builder.String()
}

func GenerateTableStringWithColors(header []string, lines [][]string) string {
	editLineWithColor(header, red)
	for i := range lines {
		editLineWithColor(lines[i], yellow)
	}
	return GenerateTableString(header, lines)
}

func editLineWithColor(line []string, color string) {
	maxInd := len(line) - 1
	if maxInd < 0 {
		return
	}
	line[0] = color + line[0]
	line[maxInd] = line[maxInd] + reset

}
