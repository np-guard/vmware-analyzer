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

	"github.com/np-guard/vmware-analyzer/internal/common"
)

const stringFormat = "%s"

var logger DefaultLogger
var once sync.Once

// DefaultLogger is the package's built-in logger. It uses log.Default() as the underlying logger.
type DefaultLogger struct {
	logLevel common.LogLevel
	l        *log.Logger
}

// NewDefaultLoggerWithVerbosity creates an instance of DefaultLogger with a user-defined log level
func NewDefaultLoggerWithLevel(level common.LogLevel) *DefaultLogger {
	return &DefaultLogger{
		logLevel: level,
		l:        log.Default(),
	}
}

// Init initializes a thread-safe singleton logger
// This would be called from a main method when the application starts up
func Init(level common.LogLevel, logFile string) error {
	// once ensures the singleton is initialized only once
	once.Do(func() {
		logger = *NewDefaultLoggerWithLevel(level)
	})
	if logFile != "" {
		return Tee(logFile)
	}
	return nil
}

func InitDefault() error {
	var level common.LogLevel
	level.SetDefault()
	return Init(level, "")
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

var logLevelValues = map[common.LogLevel]int{
	common.LogLevelFatal:  0,
	common.LogLevelError:  1,
	common.LogLevelWarn:   2,
	common.LogLevelInfo:   3,
	common.LogLevelDebug:  4,
	common.LogLevelDebug2: 5,
}

func DebugVerbosity() bool {
	return logLevelValues[logger.logLevel] >= logLevelValues[common.LogLevelDebug]
}
func InfoVerbosity() bool {
	return logLevelValues[logger.logLevel] >= logLevelValues[common.LogLevelInfo]
}
func WarningVerbosity() bool {
	return logLevelValues[logger.logLevel] >= logLevelValues[common.LogLevelWarn]
}

func ErrorVerbosity() bool {
	return logLevelValues[logger.logLevel] >= logLevelValues[common.LogLevelError]
}

// Debug/Debugf writes a debug message to the log (only if DefaultLogger verbosity is set to HighVerbosity)
func Debug(msg string) {
	debugCommonf(stringFormat, msg)
}
func Debugf(format string, o ...interface{}) {
	debugCommonf(format, o...)
}

// Debug2f for debug2 log level
func Debug2f(format string, o ...interface{}) {
	if logger.logLevel == common.LogLevelDebug2 {
		debugCommonf(format, o...)
	}
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
	if ErrorVerbosity() {
		logger.l.Printf("ERROR	%s", fmt.Sprintf(format, o...))
	}
}

func FatalError(msg string) {
	FatalErrorf(stringFormat, msg)
}

func FatalErrorf(format string, o ...interface{}) {
	// fatal error always displayed
	logger.l.Printf("FATAL	%s", fmt.Sprintf(format, o...))
	panic(fmt.Sprintf(format, o...))
}
