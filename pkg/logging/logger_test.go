package logging

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

const (
	debug2Msg = "debug2 msg"
	debugMsg  = "debug msg"
	infoMsg   = "info msg"
	warnMsg   = "warn msg"
	errMsg    = "error msg"
	fatalMsg  = "fatal msg"
	file      = "test_log.txt"
)

func gen_msgs() {
	Debug2f(debug2Msg)
	Debugf(debugMsg)
	Infof(infoMsg)
	Warnf(warnMsg)
	Errorf(errMsg)
}

func compareExpected(t *testing.T, expectedConains, expectedNotContains []string) {
	fileContent, err := os.ReadFile(file)
	require.Nil(t, err)
	for _, s := range expectedConains {
		require.Contains(t, string(fileContent), s)
	}
	for _, s := range expectedNotContains {
		require.NotContains(t, string(fileContent), s)
	}
}

func TestLogLevelsDebug2(t *testing.T) {
	require.Nil(t, Init(common.LogLevelDebug2, file))
	logger.logLevel = common.LogLevelDebug2 // required when running all unit tests at once
	gen_msgs()
	compareExpected(t, []string{debug2Msg, debugMsg, infoMsg, warnMsg, errMsg}, []string{fatalMsg})
	require.Nil(t, os.Remove(file))
}

func TestLogLevelsDebug(t *testing.T) {
	require.Nil(t, Init(common.LogLevelDebug, file))
	logger.logLevel = common.LogLevelDebug
	gen_msgs()
	compareExpected(t, []string{debugMsg, infoMsg, warnMsg, errMsg}, []string{debug2Msg, fatalMsg})
	require.Nil(t, os.Remove(file))
}

func TestLogLevelsInfo(t *testing.T) {
	require.Nil(t, Init(common.LogLevelInfo, file))
	logger.logLevel = common.LogLevelInfo
	gen_msgs()
	compareExpected(t, []string{infoMsg, warnMsg, errMsg}, []string{debugMsg, debug2Msg, fatalMsg})
	require.Nil(t, os.Remove(file))
}

func TestLogLevelsWarn(t *testing.T) {
	require.Nil(t, Init(common.LogLevelWarn, file))
	logger.logLevel = common.LogLevelWarn
	gen_msgs()
	compareExpected(t, []string{warnMsg, errMsg}, []string{infoMsg, debugMsg, debug2Msg, fatalMsg})
	require.Nil(t, os.Remove(file))
}

func TestLogLevelsErr(t *testing.T) {
	require.Nil(t, Init(common.LogLevelError, file))
	logger.logLevel = common.LogLevelError
	gen_msgs()
	compareExpected(t, []string{errMsg}, []string{warnMsg, infoMsg, debugMsg, debug2Msg, fatalMsg})
	require.Nil(t, os.Remove(file))
}

func TestLogLevelsFatal(t *testing.T) {
	require.Nil(t, Init(common.LogLevelFatal, file))
	logger.logLevel = common.LogLevelFatal
	gen_msgs()
	compareExpected(t, []string{}, []string{errMsg, warnMsg, infoMsg, debugMsg, debug2Msg, fatalMsg})
	require.Nil(t, os.Remove(file))
}

func TestLogLevelsFatalWithPanic(t *testing.T) {
	t.Run("panics", func(t *testing.T) {
		// If the function panics, recover() will
		// return a non nil value.
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("function should panic")
			}
			compareExpected(t, []string{fatalMsg}, []string{errMsg, warnMsg, infoMsg, debugMsg, debug2Msg})
			require.Nil(t, os.Remove(file))
		}()
		require.Nil(t, Init(common.LogLevelFatal, file))
		logger.logLevel = common.LogLevelFatal
		FatalErrorf(fatalMsg)
	})
}
