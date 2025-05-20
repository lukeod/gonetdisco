// Package logger provides a centralized logging system for the application
// using the slog structured logging library.
package logger

import (
	"io"
	"log/slog"
	"os"
)

// LogLevel represents the verbosity level of logging
type LogLevel int

const (
	// LevelError only logs errors
	LevelError LogLevel = iota
	// LevelWarn logs warnings and errors
	LevelWarn
	// LevelInfo logs general information, warnings, and errors
	LevelInfo
	// LevelDebug logs detailed debug information and all other levels
	LevelDebug
)

var (
	// Default logger that writes to stderr with human-readable format
	defaultLogger *slog.Logger

	// Current log level
	logLevel = LevelInfo

	// Writer for logs
	logWriter io.Writer = os.Stderr
)

// Init initializes the logging system with the specified level
func Init(level LogLevel) {
	logLevel = level

	var logHandler slog.Handler

	// Set the log level in slog
	var logLevelSlog slog.Level
	switch logLevel {
	case LevelError:
		logLevelSlog = slog.LevelError
	case LevelWarn:
		logLevelSlog = slog.LevelWarn
	case LevelInfo:
		logLevelSlog = slog.LevelInfo
	case LevelDebug:
		logLevelSlog = slog.LevelDebug
	}

	// Create handler with appropriate options
	opts := &slog.HandlerOptions{
		Level: logLevelSlog,
	}

	// Use text handler for human-readable output
	logHandler = slog.NewTextHandler(logWriter, opts)

	// Create the default logger
	defaultLogger = slog.New(logHandler)

	// Set as default slog logger
	slog.SetDefault(defaultLogger)

	Debug("Logger initialized", "level", logLevel)
}

// GetLogLevel returns the current log level
func GetLogLevel() LogLevel {
	return logLevel
}

// Error logs an error message with optional key-value pairs
func Error(msg string, args ...any) {
	slog.Error(msg, args...)
}

// Warn logs a warning message with optional key-value pairs
func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

// Info logs an informational message with optional key-value pairs
func Info(msg string, args ...any) {
	slog.Info(msg, args...)
}

// Debug logs a debug message with optional key-value pairs
func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

// WithModule returns a logger with the module name as a context attribute
func WithModule(moduleName string) *slog.Logger {
	return defaultLogger.With("module", moduleName)
}

// IsDebugEnabled checks if debug logging is enabled
func IsDebugEnabled() bool {
	return logLevel >= LevelDebug
}

// IsInfoEnabled checks if info logging is enabled
func IsInfoEnabled() bool {
	return logLevel >= LevelInfo
}
