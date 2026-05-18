package gateway

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/gorilla/websocket"
)

func isWebSocketRequest(r *http.Request) bool {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	connection := strings.ToLower(r.Header.Get("Connection"))
	if upgrade == "websocket" {
		return true
	}
	// Some proxies strip hop-by-hop headers before the gateway receives the request.
	if r.Header.Get("Sec-WebSocket-Key") != "" {
		return true
	}
	if r.Header.Get("Sec-WebSocket-Version") != "" {
		return true
	}
	return upgrade == "websocket" && strings.Contains(connection, "upgrade")
}

func proxyWebSocket(w http.ResponseWriter, r *http.Request, destURL *url.URL, route config.RouterConfig, logger *logging.Logger, wsOpts *config.WebSocketOptions) {
	if !isWebSocketRequest(r) {
		logger.Warn("Request is not a WebSocket upgrade",
			logging.String("path", r.URL.Path))
		http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
		return
	}
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" &&
		r.Header.Get("Sec-WebSocket-Key") != "" {
		r.Header.Set("Upgrade", "websocket")
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != "" {
		r.Header.Set("Connection", "Upgrade")
	}

	backendURL := buildBackendWebSocketURL(destURL, r.URL)

	dialer := websocket.Dialer{
		HandshakeTimeout: 45 * time.Second,
		Proxy:            http.ProxyFromEnvironment,
	}
	if wsOpts != nil {
		if wsOpts.HandshakeTimeout > 0 {
			dialer.HandshakeTimeout = wsOpts.HandshakeTimeout
		}
		dialer.EnableCompression = wsOpts.EnableCompression
	}
	if backendURL.Scheme == "wss" && wsOpts != nil && wsOpts.InsecureSkipVerify {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	requestHeader := http.Header{}
	for k, vv := range r.Header {
		lowerKey := strings.ToLower(k)
		switch lowerKey {
		case "upgrade", "connection", "sec-websocket-key",
			"sec-websocket-version", "sec-websocket-extensions",
			"sec-websocket-protocol":
			continue
		default:
			requestHeader[k] = vv
		}
	}

	applyUpstreamHeaders(r, requestHeader, route, wsOpts)

	logger.Debug("Dialing backend WebSocket",
		logging.String("url", backendURL.String()),
		logging.Any("headers", requestHeader))

	backendConn, resp, err := dialer.Dial(backendURL.String(), requestHeader)
	if err != nil {
		logger.Error("Failed to dial backend WebSocket", err,
			logging.String("url", backendURL.String()))

		if resp != nil {
			logger.Debug("Backend response",
				logging.Int("status", resp.StatusCode),
				logging.Any("headers", resp.Header))
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		} else {
			http.Error(w, "Unable to connect to backend", http.StatusBadGateway)
		}
		return
	}
	defer backendConn.Close()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("Failed to upgrade client connection", err)
		return
	}
	defer clientConn.Close()

	errClient := make(chan error, 1)
	errBackend := make(chan error, 1)

	replicate := func(dst, src *websocket.Conn, errc chan error) {
		for {
			msgType, msg, err := src.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseNoStatusReceived) {
					logger.Debug("WebSocket close error", logging.Error(err))
				}
				errc <- err
				return
			}
			err = dst.WriteMessage(msgType, msg)
			if err != nil {
				errc <- err
				return
			}
		}
	}

	go replicate(clientConn, backendConn, errClient)
	go replicate(backendConn, clientConn, errBackend)

	select {
	case err = <-errClient:
		logger.Debug("Client to backend connection closed", logging.Error(err))
	case err = <-errBackend:
		logger.Debug("Backend to client connection closed", logging.Error(err))
	}
}

func buildBackendWebSocketURL(destURL, requestURL *url.URL) url.URL {
	backendScheme := "ws"
	if destURL != nil && (destURL.Scheme == "https" || destURL.Scheme == "wss") {
		backendScheme = "wss"
	}

	path := "/"
	if destURL != nil && strings.TrimSpace(destURL.Path) != "" {
		path = destURL.Path
	} else if requestURL != nil && strings.TrimSpace(requestURL.Path) != "" {
		path = requestURL.Path
	}

	rawQuery := ""
	if requestURL != nil {
		rawQuery = requestURL.RawQuery
	}

	host := ""
	if destURL != nil {
		host = destURL.Host
	}

	return url.URL{
		Scheme:   backendScheme,
		Host:     host,
		Path:     path,
		RawQuery: rawQuery,
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func websocketDial(r *http.Request, backendAddr string) (net.Conn, error) {
	u, err := url.Parse(backendAddr)
	if err != nil {
		return nil, err
	}
	return net.Dial("tcp", u.Host)
}

func copyWebSocketData(dst net.Conn, src net.Conn, errc chan error) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, werr := dst.Write(buf[:n])
			fmt.Printf("[copyWebSocketData] Wrote %d bytes to %T\n", written, dst)
			if werr != nil {
				errc <- werr
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				fmt.Printf("[copyWebSocketData] Error: %v\n", err)
			}
			errc <- err
			return
		}
	}
}
