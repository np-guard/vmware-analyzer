/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const stringFormat = "%s"

var logger DefaultLogger
var once sync.Once

// Verbosity is an enumerated type for defining the level of verbosity.
type Verbosity int

const (
	LowVerbosity    Verbosity = iota // LowVerbosity only reports errors
	MediumVerbosity                  // MediumVerbosity reports warnings and errors
	HighVerbosity                    // HighVerbosity reports infos, warnings and errors
)

// DefaultLogger is the package's built-in logger. It uses log.Default() as the underlying logger.
type DefaultLogger struct {
	verbosity Verbosity
	l         *log.Logger
}

// NewDefaultLoggerWithVerbosity creates an instance of DefaultLogger with a user-defined verbosity.
func NewDefaultLoggerWithVerbosity(verbosity Verbosity) *DefaultLogger {
	return &DefaultLogger{
		verbosity: verbosity,
		l:         log.Default(),
	}
}

// Init initializes a thread-safe singleton logger
// This would be called from a main method when the application starts up
func Init(verbosity Verbosity, logFile string) error {
	// once ensures the singleton is initialized only once
	once.Do(func() {
		logger = *NewDefaultLoggerWithVerbosity(verbosity)
	})
	if logFile != "" {
		return Tee(logFile)
	}
	return nil
}

// Tee() redirect the output into the default log, and a file
func Tee(fileName string) error {
	err := os.MkdirAll(filepath.Dir(fileName), os.ModePerm)
	if err != nil {
		return err
	}
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	w := io.MultiWriter(log.Default().Writer(), f)
	logger.l = log.New(w, "", log.LstdFlags)
	return nil
}

func DebugVerbosity() bool   { return logger.verbosity == HighVerbosity }
func InfoVerbosity() bool    { return logger.verbosity == HighVerbosity }
func WarningVerbosity() bool { return logger.verbosity >= MediumVerbosity }

// Debug/Debugf writes a debug message to the log (only if DefaultLogger verbosity is set to HighVerbosity)
func Debug(msg string) {
	debugCommonf(stringFormat, msg)
}
func Debugf(format string, o ...interface{}) {
	debugCommonf(format, o...)
}

func debugCommonf(format string, o ...interface{}) {
	if DebugVerbosity() {
		pc, _, _, _ := runtime.Caller(2)
		details := runtime.FuncForPC(pc)
		logger.l.Printf("DEBUG	%s	%s", details.Name(), fmt.Sprintf(format, o...))
	}
}

// Infof writes an informative message to the log (only if DefaultLogger verbosity is set to HighVerbosity)
func Infof(format string, o ...interface{}) {
	if InfoVerbosity() {
		logger.l.Printf("INFO	%s", fmt.Sprintf(format, o...))
	}
}

func Warn(msg string) {
	Warnf(stringFormat, msg)
}

// Warnf writes a warning message to the log (unless DefaultLogger verbosity is set to LowVerbosity)
func Warnf(format string, o ...interface{}) {
	if WarningVerbosity() {
		logger.l.Printf("WARN	%s", fmt.Sprintf(format, o...))
	}
}

// Errorf writes an error message to the log
func Errorf(format string, o ...interface{}) {
	logger.l.Printf("ERROR	%s", fmt.Sprintf(format, o...))
}

func InternalError(msg string) {
	InternalErrorf(stringFormat, msg)
}

func InternalErrorf(format string, o ...interface{}) {
	logger.l.Printf("INTERNAL ERROR	%s", fmt.Sprintf(format, o...))
	panic(fmt.Sprintf(format, o...))
}
