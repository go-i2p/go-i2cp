package go_i2cp

import "fmt"

type LoggerTags = uint32

var logInstance = &Logger{}

// TODO filter
func LogInit(callbacks *LoggerCallbacks, level int) {
	logInstance = &Logger{callbacks: callbacks}
	logInstance.setLogLevel(level)
}
func Debug(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|DEBUG, message)
		return
	}
	logInstance.log(tags|DEBUG, message, args...)
}
func Info(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|INFO, message)
		return
	}
	logInstance.log(tags|INFO, message, args...)
	//logInstance.log(tags|INFO, message, args...)
}
func Warning(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|WARNING, message)
		return
	}
	logInstance.log(tags|WARNING, message, args...)
	//logInstance.log(tags|WARNING, message, args...)
}
func Error(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|ERROR, message)
		return
	}
	logInstance.log(tags|ERROR, message, args...)
	//logInstance.log(tags|ERROR, message, args...)
}
func Fatal(tags LoggerTags, message string, args ...interface{}) {
	if len(args) == 0 {
		logInstance.log(tags|FATAL, message)
		return
	}
	logInstance.log(tags|FATAL, message, args...)
	//logInstance.log(tags|FATAL, message, args...)
}

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
