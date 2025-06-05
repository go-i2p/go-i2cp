package go_i2cp

import "fmt"

// LoggerTags defines the type for logger tags
// Moved from: logger.go
type LoggerTags = uint32

func (l *Logger) log(tags LoggerTags, format string, args ...interface{}) {
	if len(args) != 0 {
		if l.callbacks == nil {
			fmt.Printf(format+"\n", args)
		} else {
			l.callbacks.onLog(l, tags, fmt.Sprintf(format, args...))
		}
		return
	}
	if l.callbacks == nil {
		fmt.Printf(format + "\n")
	} else {
		l.callbacks.onLog(l, tags, fmt.Sprintf(format))
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
