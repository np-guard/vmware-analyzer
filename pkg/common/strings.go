package common

import (
	"slices"
	"strings"
)

const (
	OutputSectionSep = "\n-------------------------------------------------------------------\n"
	ShortSep         = "\n-------------------------\n"

	// ANSI escape codes - for colored output printed to the terminal
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Yellow  = "\033[33m"
	Green   = "\033[32m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Gray    = "\033[37m"
	White   = "\033[97m"
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
