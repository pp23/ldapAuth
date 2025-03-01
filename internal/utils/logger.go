package utils

import (
	"io/ioutil"
	"log"
	"os"
)

type Logger struct {
	// LoggerDEBUG level.
	DEBUG *log.Logger
	// LoggerINFO level.
	INFO *log.Logger
	// LoggerERROR level.
	ERROR *log.Logger
}

func NewLogger() *Logger {
	logger := &Logger{
		DEBUG: log.New(ioutil.Discard, "DEBUG: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile),
		INFO:  log.New(ioutil.Discard, "INFO: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile),
		ERROR: log.New(ioutil.Discard, "ERROR: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile),
	}
	return logger
}

// define stdout loggers based in logLevel conf.
func (logger *Logger) SetLevel(level string) {
	switch level {
	case "ERROR":
		logger.ERROR.SetOutput(os.Stderr)
	case "INFO":
		logger.ERROR.SetOutput(os.Stderr)
		logger.INFO.SetOutput(os.Stdout)
	case "DEBUG":
		logger.ERROR.SetOutput(os.Stderr)
		logger.INFO.SetOutput(os.Stdout)
		logger.DEBUG.SetOutput(os.Stdout)
	default:
		logger.ERROR.SetOutput(os.Stderr)
		logger.INFO.SetOutput(os.Stdout)
	}
}
