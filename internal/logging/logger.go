package logging

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap.Logger for structured logging
type Logger struct {
	logger *zap.Logger
}

// NewLogger creates a new logger instance
func NewLogger(debug bool) *Logger {
	var config zap.Config

	if debug {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	logger, err := config.Build()
	if err != nil {
		// Fallback to basic logger if zap fails
		basicLogger, _ := zap.NewProduction()
		return &Logger{logger: basicLogger}
	}

	return &Logger{logger: logger}
}

// NewLoggerFromEnv creates a logger based on environment variables
func NewLoggerFromEnv() *Logger {
	debug := os.Getenv("LOG_LEVEL") == "debug"
	return NewLogger(debug)
}

// Info logs an info level message
func (l *Logger) Info(msg string, fields ...zap.Field) {
	l.logger.Info(msg, fields...)
}

// Error logs an error level message
func (l *Logger) Error(msg string, err error, fields ...zap.Field) {
	if err != nil {
		fields = append(fields, zap.Error(err))
	}
	l.logger.Error(msg, fields...)
}

// Warn logs a warning level message
func (l *Logger) Warn(msg string, fields ...zap.Field) {
	l.logger.Warn(msg, fields...)
}

// Debug logs a debug level message
func (l *Logger) Debug(msg string, fields ...zap.Field) {
	l.logger.Debug(msg, fields...)
}

// Fatal logs a fatal level message and exits
func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	l.logger.Fatal(msg, fields...)
}

// With creates a child logger with additional fields
func (l *Logger) With(fields ...zap.Field) *Logger {
	return &Logger{logger: l.logger.With(fields...)}
}

// WithContext creates a logger with request context
func (l *Logger) WithContext(ctx map[string]interface{}) *Logger {
	fields := make([]zap.Field, 0, len(ctx))
	for k, v := range ctx {
		fields = append(fields, zap.Any(k, v))
	}
	return l.With(fields...)
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.logger.Sync()
}

// Helper functions for common logging patterns
func (l *Logger) LogRequest(method, path string, statusCode int, duration float64) {
	l.Info("HTTP Request",
		zap.String("method", method),
		zap.String("path", path),
		zap.Int("status", statusCode),
		zap.Float64("duration_ms", duration),
	)
}

func (l *Logger) LogConfigLoad(path string, err error) {
	if err != nil {
		l.Error("Failed to load configuration", err,
			zap.String("path", path),
		)
	} else {
		l.Info("Configuration loaded successfully",
			zap.String("path", path),
		)
	}
}

func (l *Logger) LogPluginEvent(pluginName, event string, err error) {
	if err != nil {
		l.Error("Plugin event failed", err,
			zap.String("plugin", pluginName),
			zap.String("event", event),
		)
	} else {
		l.Info("Plugin event completed",
			zap.String("plugin", pluginName),
			zap.String("event", event),
		)
	}
}

func (l *Logger) LogGatewayStart(port int) {
	l.Info("Gateway starting",
		zap.Int("port", port),
	)
}

func (l *Logger) LogGatewayStop() {
	l.Info("Gateway shutting down")
}

// Field helpers for common types
func String(key, val string) zap.Field {
	return zap.String(key, val)
}

func Int(key string, val int) zap.Field {
	return zap.Int(key, val)
}

func Float64(key string, val float64) zap.Field {
	return zap.Float64(key, val)
}

func Bool(key string, val bool) zap.Field {
	return zap.Bool(key, val)
}

func Error(err error) zap.Field {
	return zap.Error(err)
}

func Any(key string, val interface{}) zap.Field {
	return zap.Any(key, val)
}

func Duration(key string, val time.Duration) zap.Field {
	return zap.Duration(key, val)
}

func Int64(key string, val int64) zap.Field {
	return zap.Int64(key, val)
}
