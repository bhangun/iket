package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"

	"github.com/bhangun/iket/pkg/config"
)

type http3Transport interface {
	ListenAndServe() error
	Shutdown(context.Context) error
	SetQUICHeaders(http.Header) error
}

func buildServerTLSConfig(tlsCfg config.TLSConfig) (*tls.Config, error) {
	serverTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	switch tlsCfg.MinVersion {
	case "TLS1.0":
		serverTLSConfig.MinVersion = tls.VersionTLS10
	case "TLS1.1":
		serverTLSConfig.MinVersion = tls.VersionTLS11
	case "TLS1.2":
		serverTLSConfig.MinVersion = tls.VersionTLS12
	case "TLS1.3":
		serverTLSConfig.MinVersion = tls.VersionTLS13
	}

	if tlsCfg.ClientCAFile != "" {
		caPool, err := loadClientCAPool(tlsCfg.ClientCAFile)
		if err != nil {
			return nil, err
		}
		serverTLSConfig.ClientCAs = caPool
		switch tlsCfg.ClientAuthType {
		case "RequestClientCert":
			serverTLSConfig.ClientAuth = tls.RequestClientCert
		case "RequireAnyClientCert":
			serverTLSConfig.ClientAuth = tls.RequireAnyClientCert
		case "VerifyClientCertIfGiven":
			serverTLSConfig.ClientAuth = tls.VerifyClientCertIfGiven
		case "RequireAndVerifyClientCert":
			serverTLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		default:
			serverTLSConfig.ClientAuth = tls.NoClientCert
		}
	}

	return serverTLSConfig, nil
}

func loadClientCAPool(path string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read client CA file: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append client CA certificate to pool")
	}
	return caPool, nil
}

func buildHTTP3Transport(tlsCfg config.TLSConfig, handler http.Handler) (http3Transport, error) {
	if !tlsCfg.HTTP3Enabled {
		return nil, nil
	}

	tlsPort := tlsCfg.EffectivePort(0)
	http3Port := tlsCfg.EffectiveHTTP3Port(tlsPort)
	serverTLSConfig, err := buildServerTLSConfig(tlsCfg)
	if err != nil {
		return nil, err
	}
	quicTLSConfig := http3.ConfigureTLSConfig(serverTLSConfig)
	if quicTLSConfig.MinVersion < tls.VersionTLS13 {
		quicTLSConfig.MinVersion = tls.VersionTLS13
	}
	cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load HTTP/3 certificate pair: %w", err)
	}
	quicTLSConfig.Certificates = []tls.Certificate{cert}

	return &http3.Server{
		Addr:            fmt.Sprintf(":%d", http3Port),
		Port:            http3Port,
		Handler:         handler,
		TLSConfig:       quicTLSConfig,
		EnableDatagrams: tlsCfg.HTTP3Datagrams,
	}, nil
}

func wrapHandlerWithHTTP3Advertisement(next http.Handler, transport http3Transport) http.Handler {
	if next == nil || transport == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.TLS != nil {
			_ = transport.SetQUICHeaders(w.Header())
		}
		next.ServeHTTP(w, r)
	})
}
