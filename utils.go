package go_i2cp

import (
	"bufio"
	"crypto/dsa"
	"os"
	"regexp"
	"strings"
)

// Global variables
// Moved from: logger.go
var logInstance = &Logger{}

// Moved from: session_config.go
var configRegex = regexp.MustCompile("\\s*([\\w.]+)=\\s*(.+)\\s*;\\s*")

// Logging utility functions
// Moved from: logger.go

// LogInit initializes the logger with callbacks and level
// TODO filter
func LogInit(callbacks *LoggerCallbacks, level int) {
	logInstance = &Logger{callbacks: callbacks}
	logInstance.setLogLevel(level)
}

// Debug logs a debug message with optional arguments
func Debug(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|DEBUG, message)
		return
	}
	logInstance.log(tags|DEBUG, message, args...)
}

// Info logs an info message with optional arguments
func Info(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|INFO, message)
		return
	}
	logInstance.log(tags|INFO, message, args...)
}

// Warning logs a warning message with optional arguments
func Warning(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|WARNING, message)
		return
	}
	logInstance.log(tags|WARNING, message, args...)
}

// Error logs an error message with optional arguments
func Error(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|ERROR, message)
		return
	}
	logInstance.log(tags|ERROR, message, args...)
}

// Fatal logs a fatal message with optional arguments
func Fatal(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|FATAL, message)
		return
	}
	logInstance.log(tags|FATAL, message, args...)
}

// Config parsing utility functions
// Moved from: session_config.go

// ParseConfig parses a configuration file and calls the callback for each key-value pair
func ParseConfig(s string, cb func(string, string)) {
	file, err := os.Open(s)
	if err != nil {
		if !strings.Contains(err.Error(), "no such file") {
			Error(SESSION_CONFIG, err.Error())
		}
		return
	}
	Debug(SESSION_CONFIG, "Parsing config file '%s'", s)
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
		Error(SESSION_CONFIG, "reading input from %s config %s", s, err.Error())
	}
}

// Crypto utility functions
// Moved from: crypto.go

// GetCryptoInstance returns the global crypto instance
func GetCryptoInstance() *Crypto {
	if first == 0 {
		dsa.GenerateParameters(&singleton.params, singleton.rng, dsa.L1024N160)
	}
	first++
	return &singleton
}
