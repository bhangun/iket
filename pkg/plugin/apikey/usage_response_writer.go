package apikey

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"time"
)

type clientUsageOutcome struct {
	statusCode     int
	bytesWritten   int64
	durationMillis int64
}

type clientUsageResponseWriter struct {
	http.ResponseWriter
	wroteHeader  bool
	statusCode   int
	bytesWritten int64
}

func newClientUsageResponseWriter(w http.ResponseWriter) *clientUsageResponseWriter {
	return &clientUsageResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (w *clientUsageResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	if statusCode <= 0 {
		statusCode = http.StatusOK
	}
	w.wroteHeader = true
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *clientUsageResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(body)
	w.bytesWritten += int64(n)
	return n, err
}

func (w *clientUsageResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *clientUsageResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := readerFrom.ReadFrom(reader)
		w.bytesWritten += n
		return n, err
	}
	n, err := io.Copy(w.ResponseWriter, reader)
	w.bytesWritten += n
	return n, err
}

func (w *clientUsageResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *clientUsageResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func (w *clientUsageResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *clientUsageResponseWriter) CloseNotify() <-chan bool {
	closeNotifier, ok := w.ResponseWriter.(http.CloseNotifier)
	if !ok {
		return make(chan bool)
	}
	return closeNotifier.CloseNotify()
}

func (w *clientUsageResponseWriter) clientUsageOutcome(duration time.Duration) clientUsageOutcome {
	statusCode := w.statusCode
	if statusCode <= 0 {
		statusCode = http.StatusOK
	}
	durationMillis := duration.Milliseconds()
	if duration > 0 && durationMillis == 0 {
		durationMillis = 1
	}
	return clientUsageOutcome{
		statusCode:     statusCode,
		bytesWritten:   w.bytesWritten,
		durationMillis: durationMillis,
	}
}
