package go_i2cp

import (
	"fmt"

	"github.com/go-i2p/logger"
)

// LoggerTags defines the type for logger tags
// Moved from: logger.go
type LoggerTags = uint32

func (l *Logger) log(tags LoggerTags, format string, args ...interface{}) {
	// Use go-i2p/logger exclusively
	log := logger.GetGoI2PLogger()
	if len(args) != 0 {
		if l.callbacks == nil {
			log.Warnf(format, args...)
		} else {
			l.callbacks.onLog(l, tags, fmt.Sprintf(format, args...))
		}
		return
	}
	if l.callbacks == nil {
		log.Warn(format)
	} else {
		l.callbacks.onLog(l, tags, format)
	}
}

func (l *Logger) setLogLevel(level int) {
	switch level {
	case DEBUG:
	case INFO:
	case WARNING:
	case ERROR:
	case FATAL:
		l.logLevel = level
	default:
		l.logLevel = ERROR
	}
}
