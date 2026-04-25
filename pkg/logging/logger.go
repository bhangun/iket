package logging

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger wraps zap.Logger for structured logging
type Logger struct {
	logger *zap.Logger
	store  *logStore
}

type logStore struct {
	mu          sync.RWMutex
	entries     []LogEntry
	maxEntries  int
	subscribers map[chan LogEntry]struct{}
}

type teeCore struct {
	zapcore.Core
	store *logStore
}

func newLogStore(maxEntries int) *logStore {
	return &logStore{
		maxEntries:  maxEntries,
		subscribers: make(map[chan LogEntry]struct{}),
	}
}

func (c *teeCore) With(fields []zapcore.Field) zapcore.Core {
	return &teeCore{
		Core:  c.Core.With(fields),
		store: c.store,
	}
}

func (c *teeCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

func (c *teeCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if err := c.Core.Write(entry, fields); err != nil {
		return err
	}
	c.store.append(newLogEntry(entry, fields))
	return nil
}

type mapObjectEncoder struct {
	fields map[string]interface{}
}

func newMapObjectEncoder() *mapObjectEncoder {
	return &mapObjectEncoder{fields: make(map[string]interface{})}
}

func (e *mapObjectEncoder) AddArray(key string, v zapcore.ArrayMarshaler) error {
	e.fields[key] = "[array]"
	return nil
}
func (e *mapObjectEncoder) AddObject(key string, v zapcore.ObjectMarshaler) error {
	e.fields[key] = "[object]"
	return nil
}
func (e *mapObjectEncoder) AddBinary(key string, v []byte)          { e.fields[key] = string(v) }
func (e *mapObjectEncoder) AddByteString(key string, v []byte)      { e.fields[key] = string(v) }
func (e *mapObjectEncoder) AddBool(key string, v bool)              { e.fields[key] = v }
func (e *mapObjectEncoder) AddComplex128(key string, v complex128)  { e.fields[key] = v }
func (e *mapObjectEncoder) AddComplex64(key string, v complex64)    { e.fields[key] = v }
func (e *mapObjectEncoder) AddDuration(key string, v time.Duration) { e.fields[key] = v.String() }
func (e *mapObjectEncoder) AddFloat64(key string, v float64)        { e.fields[key] = v }
func (e *mapObjectEncoder) AddFloat32(key string, v float32)        { e.fields[key] = v }
func (e *mapObjectEncoder) AddInt(key string, v int)                { e.fields[key] = v }
func (e *mapObjectEncoder) AddInt64(key string, v int64)            { e.fields[key] = v }
func (e *mapObjectEncoder) AddInt32(key string, v int32)            { e.fields[key] = v }
func (e *mapObjectEncoder) AddInt16(key string, v int16)            { e.fields[key] = v }
func (e *mapObjectEncoder) AddInt8(key string, v int8)              { e.fields[key] = v }
func (e *mapObjectEncoder) AddString(key, v string)                 { e.fields[key] = v }
func (e *mapObjectEncoder) AddTime(key string, v time.Time) {
	e.fields[key] = v.Format(time.RFC3339Nano)
}
func (e *mapObjectEncoder) AddUint(key string, v uint)       { e.fields[key] = v }
func (e *mapObjectEncoder) AddUint64(key string, v uint64)   { e.fields[key] = v }
func (e *mapObjectEncoder) AddUint32(key string, v uint32)   { e.fields[key] = v }
func (e *mapObjectEncoder) AddUint16(key string, v uint16)   { e.fields[key] = v }
func (e *mapObjectEncoder) AddUint8(key string, v uint8)     { e.fields[key] = v }
func (e *mapObjectEncoder) AddUintptr(key string, v uintptr) { e.fields[key] = v }
func (e *mapObjectEncoder) AddReflected(key string, v interface{}) error {
	e.fields[key] = v
	return nil
}
func (e *mapObjectEncoder) OpenNamespace(key string) {}
func (e *mapObjectEncoder) AddStringer(key string, v interface{ String() string }) {
	e.fields[key] = v.String()
}

func newLogEntry(entry zapcore.Entry, fields []zapcore.Field) LogEntry {
	enc := newMapObjectEncoder()
	for _, field := range fields {
		field.AddTo(enc)
	}
	return LogEntry{
		Timestamp: entry.Time,
		Level:     entry.Level.String(),
		Message:   entry.Message,
		Fields:    enc.fields,
	}
}

func (s *logStore) append(entry LogEntry) {
	s.mu.Lock()
	if len(s.entries) >= s.maxEntries {
		copy(s.entries, s.entries[1:])
		s.entries[len(s.entries)-1] = entry
	} else {
		s.entries = append(s.entries, entry)
	}

	subscribers := make([]chan LogEntry, 0, len(s.subscribers))
	for ch := range s.subscribers {
		subscribers = append(subscribers, ch)
	}
	s.mu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
}

func (s *logStore) recent(limit int, level string) []LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filtered := make([]LogEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		if level != "" && !strings.EqualFold(entry.Level, level) {
			continue
		}
		filtered = append(filtered, entry)
	}

	if limit <= 0 || limit > len(filtered) {
		limit = len(filtered)
	}
	start := len(filtered) - limit
	if start < 0 {
		start = 0
	}
	out := make([]LogEntry, len(filtered[start:]))
	copy(out, filtered[start:])
	return out
}

func (s *logStore) subscribe() chan LogEntry {
	ch := make(chan LogEntry, 128)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

func (s *logStore) unsubscribe(ch chan LogEntry) {
	s.mu.Lock()
	if _, ok := s.subscribers[ch]; ok {
		delete(s.subscribers, ch)
		close(ch)
	}
	s.mu.Unlock()
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

	store := newLogStore(2000)
	logger, err := config.Build(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return &teeCore{Core: core, store: store}
	}))
	if err != nil {
		basicLogger, _ := zap.NewProduction()
		logger = basicLogger
	}

	return &Logger{logger: logger, store: store}
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
	return &Logger{logger: l.logger.With(fields...), store: l.store}
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

func (l *Logger) RecentLogs(limit int, level string) []LogEntry {
	if l == nil || l.store == nil {
		return nil
	}
	return l.store.recent(limit, level)
}

func (l *Logger) SubscribeLogs() chan LogEntry {
	if l == nil || l.store == nil {
		ch := make(chan LogEntry)
		close(ch)
		return ch
	}
	return l.store.subscribe()
}

func (l *Logger) UnsubscribeLogs(ch chan LogEntry) {
	if l == nil || l.store == nil {
		return
	}
	l.store.unsubscribe(ch)
}

func (e LogEntry) JSON() string {
	data, _ := json.Marshal(e)
	return string(data)
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
