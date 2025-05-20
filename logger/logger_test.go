package logger

import (
	"bytes"
	"testing"
)

// TestInit verifies that the logger is initialized correctly
func TestInit(t *testing.T) {
	// Save the original log writer to restore later
	originalWriter := logWriter
	defer func() {
		logWriter = originalWriter
	}()

	// Create a buffer to capture log output
	var buf bytes.Buffer
	logWriter = &buf

	// Initialize the logger with different levels and verify
	testCases := []struct {
		level LogLevel
		name  string
	}{
		{LevelError, "error"},
		{LevelWarn, "warn"},
		{LevelInfo, "info"},
		{LevelDebug, "debug"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize with test level
			Init(tc.level)

			// Verify the level was set
			if GetLogLevel() != tc.level {
				t.Errorf("Expected log level %v, got %v", tc.level, GetLogLevel())
			}
		})
	}
}

// TestLogFunctions verifies that the logging functions work correctly
func TestLogFunctions(t *testing.T) {
	// Save the original log writer to restore later
	originalWriter := logWriter
	defer func() {
		logWriter = originalWriter
	}()

	// Create a buffer to capture log output
	var buf bytes.Buffer
	logWriter = &buf

	// Initialize with debug level to capture all logs
	Init(LevelDebug)

	// Test each log function
	Error("test error", "key", "value")
	if !bytes.Contains(buf.Bytes(), []byte("ERROR")) || !bytes.Contains(buf.Bytes(), []byte("test error")) {
		t.Error("Error log not captured correctly")
	}
	buf.Reset()

	Warn("test warning", "key", "value")
	if !bytes.Contains(buf.Bytes(), []byte("WARN")) || !bytes.Contains(buf.Bytes(), []byte("test warning")) {
		t.Error("Warning log not captured correctly")
	}
	buf.Reset()

	Info("test info", "key", "value")
	if !bytes.Contains(buf.Bytes(), []byte("INFO")) || !bytes.Contains(buf.Bytes(), []byte("test info")) {
		t.Error("Info log not captured correctly")
	}
	buf.Reset()

	Debug("test debug", "key", "value")
	if !bytes.Contains(buf.Bytes(), []byte("DEBUG")) || !bytes.Contains(buf.Bytes(), []byte("test debug")) {
		t.Error("Debug log not captured correctly")
	}
	buf.Reset()
}

// TestWithModule verifies the module context is set correctly
func TestWithModule(t *testing.T) {
	// Save the original log writer to restore later
	originalWriter := logWriter
	defer func() {
		logWriter = originalWriter
	}()

	// Create a buffer to capture log output
	var buf bytes.Buffer
	logWriter = &buf

	// Initialize with debug level to capture all logs
	Init(LevelDebug)

	// Create a module logger and verify it adds the module attribute
	moduleLogger := WithModule("test-module")
	moduleLogger.Info("module test")

	if !bytes.Contains(buf.Bytes(), []byte("module=test-module")) {
		t.Error("Module attribute not added correctly")
	}
}

// TestIsLevelEnabled verifies the level check functions
func TestIsLevelEnabled(t *testing.T) {
	// Test debug level checks
	Init(LevelDebug)
	if !IsDebugEnabled() {
		t.Error("Debug should be enabled at LevelDebug")
	}
	if !IsInfoEnabled() {
		t.Error("Info should be enabled at LevelDebug")
	}

	// Test info level checks
	Init(LevelInfo)
	if IsDebugEnabled() {
		t.Error("Debug should not be enabled at LevelInfo")
	}
	if !IsInfoEnabled() {
		t.Error("Info should be enabled at LevelInfo")
	}

	// Test warn level checks
	Init(LevelWarn)
	if IsDebugEnabled() {
		t.Error("Debug should not be enabled at LevelWarn")
	}
	if IsInfoEnabled() {
		t.Error("Info should not be enabled at LevelWarn")
	}

	// Test error level checks
	Init(LevelError)
	if IsDebugEnabled() {
		t.Error("Debug should not be enabled at LevelError")
	}
	if IsInfoEnabled() {
		t.Error("Info should not be enabled at LevelError")
	}
}