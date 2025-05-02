package main

import (
	"log"
	"net/http"
)

// / ---------------
// Logger provides structured logging for the gateway
type Logger struct {
	enableLogging bool
}

// NewLogger creates a new logger instance
func NewLogger(enableLogging bool) *Logger {
	return &Logger{
		enableLogging: enableLogging,
	}
}

// Info logs informational messages
func (l *Logger) Info(format string, v ...interface{}) {
	if l.enableLogging {
		log.Printf("[INFO] "+format, v...)
	}
}

// Error logs error messages
func (l *Logger) Error(format string, v ...interface{}) {
	if l.enableLogging {
		log.Printf("[ERROR] "+format, v...)
	}
}

// Warn logs warning messages
func (l *Logger) Warn(format string, v ...interface{}) {
	if l.enableLogging {
		log.Printf("[WARN] "+format, v...)
	}
}

// loggingResponseWriter is a custom response writer that captures the status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

// newLoggingResponseWriter creates a new logging response writer
func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK, 0}
}

// WriteHeader captures the status code
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Write captures the number of bytes written
func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.bytesWritten += n
	return n, err
}
