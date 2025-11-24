package go_i2cp

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/go-i2p/logger"
)

// Moved from: session_config.go
var configRegex = regexp.MustCompile("\\s*([\\w.]+)=\\s*(.+)\\s*;\\s*")

// Logging utility functions
// Moved from: logger.go

// LogInit initializes the logger with the specified level
// Deprecated: Use github.com/go-i2p/logger directly for new code
func LogInit(level int) {
	// Initialize go-i2p/logger
	logger.InitializeGoI2PLogger()

	switch level {
	case DEBUG:
		os.Setenv("DEBUG_I2P", "debug")
	case INFO:
		os.Setenv("DEBUG_I2P", "debug")
	case WARNING:
		os.Setenv("DEBUG_I2P", "warn")
	case ERROR:
		os.Setenv("DEBUG_I2P", "error")
	case FATAL:
		os.Setenv("DEBUG_I2P", "fatal")
		os.Setenv("WARNFAIL_I2P", "true")
	default:
		os.Setenv("DEBUG_I2P", "debug")
	}
}

// Debug logs a debug message with optional arguments.
// Deprecated: Use github.com/go-i2p/logger directly for new code.
// The tags parameter has been removed; use logger.Debug() or logger.Debugf() instead.
func Debug(message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.Debug(message)
		return
	}
	logInstance.Debugf(message, args...)
}

// Info logs an info message with optional arguments.
// Deprecated: Use github.com/go-i2p/logger directly for new code.
// The tags parameter has been removed; use logger.Warn() or logger.Warnf() instead.
// Note: Info maps to Warn level in the logger.
func Info(message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.Warn(message)
		return
	}
	logInstance.Warnf(message, args...)
}

// Warning logs a warning message with optional arguments.
// Deprecated: Use github.com/go-i2p/logger directly for new code.
// The tags parameter has been removed; use logger.Warn() or logger.Warnf() instead.
func Warning(message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.Warn(message)
		return
	}
	logInstance.Warnf(message, args...)
}

// Error logs an error message with optional arguments.
// Deprecated: Use github.com/go-i2p/logger directly for new code.
// The tags parameter has been removed; use logger.Error() or logger.Errorf() instead.
func Error(message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.Error(message)
		return
	}
	logInstance.Errorf(message, args...)
}

// Fatal logs a fatal message with optional arguments.
// Deprecated: Use github.com/go-i2p/logger directly for new code.
// The tags parameter has been removed; use logger.Error() or logger.Errorf() instead.
// Note: Fatal maps to Error level in the logger and sets WARNFAIL_I2P.
func Fatal(message string, args ...interface{}) {
	os.Setenv("WARNFAIL_I2P", "true")
	if len(args) == 0 {
		logInstance.Error(message)
		return
	}
	logInstance.Errorf(message, args...)
}

// Config parsing utility functions
// Moved from: session_config.go

// ParseConfig parses a configuration file and calls the callback for each key-value pair
func ParseConfig(s string, cb func(string, string)) {
	file, err := os.Open(s)
	if err != nil {
		if !strings.Contains(err.Error(), "no such file") {
			Error("%s", err.Error())
		}
		return
	}
	Debug("Parsing config file '%s'", s)
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		line := scan.Text()
		groups := configRegex.FindStringSubmatch(line)
		if len(groups) != 3 {
			continue
		}
		cb(groups[1], groups[2])
	}
	if err := scan.Err(); err != nil {
		Error("reading input from %s config %s", s, err.Error())
	}
}

// Crypto utility functions
// Moved from: crypto.go

// NewCryptoInstance creates a new crypto instance
func NewCryptoInstance() *Crypto {
	return NewCrypto()
}

// parseIntWithDefault parses an integer string with a default value if parsing fails
func parseIntWithDefault(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}

	// Simple integer parsing without external dependencies
	result := 0
	negative := false
	start := 0

	if len(s) > 0 && s[0] == '-' {
		negative = true
		start = 1
	}

	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return defaultValue // Invalid character, return default
		}
		result = result*10 + int(s[i]-'0')
	}

	if negative {
		result = -result
	}

	return result
}
