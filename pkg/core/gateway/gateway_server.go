package gateway

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

// Serve starts the gateway server.
func (g *Gateway) Serve(ctx context.Context) error {
	g.logger.Info("Starting gateway server", logging.Int("port", g.config.Server.Port))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", g.config.Server.Port),
		Handler: AccessLogMiddleware(g, g.router),
	}

	g.server = server
	tlsPort := g.config.Security.TLS.EffectivePort(g.config.Server.Port)
	http3Transport, err := buildHTTP3Transport(g.config.Security.TLS, AccessLogMiddleware(g, g.router))
	if err != nil {
		return fmt.Errorf("failed to prepare HTTP/3 transport: %w", err)
	}
	g.http3Server = http3Transport

	if !g.config.Security.TLS.Enabled || tlsPort != g.config.Server.Port {
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				g.logger.Error("Server error", err)
			}
		}()
	}

	if g.config.Security.TLS.Enabled {
		if err := config.EnsureTLSAssets(g.config.Security.TLS); err != nil {
			return fmt.Errorf("failed to prepare TLS assets: %w", err)
		}

		tlsConfig, err := buildServerTLSConfig(g.config.Security.TLS)
		if err != nil {
			return err
		}

		if http3Transport != nil {
			go func() {
				http3Port := g.config.Security.TLS.EffectiveHTTP3Port(tlsPort)
				g.logger.Info("Starting HTTP/3 server", logging.Int("port", http3Port), logging.String("cert", g.config.Security.TLS.CertFile))
				if err := http3Transport.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					g.logger.Error("HTTP/3 server error", err)
				}
			}()
		}

		if tlsPort == g.config.Server.Port {
			server.Handler = wrapHandlerWithHTTP3Advertisement(AccessLogMiddleware(g, g.router), http3Transport)
			go func() {
				g.logger.Info("Starting TLS server", logging.Int("port", tlsPort), logging.String("cert", g.config.Security.TLS.CertFile))
				if err := server.ListenAndServeTLS(g.config.Security.TLS.CertFile, g.config.Security.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
					g.logger.Error("TLS Server error", err)
				}
			}()
			g.tlsServer = server
		} else {
			tlsServer := &http.Server{
				Addr:      fmt.Sprintf(":%d", tlsPort),
				Handler:   wrapHandlerWithHTTP3Advertisement(AccessLogMiddleware(g, g.router), http3Transport),
				TLSConfig: tlsConfig,
			}
			g.tlsServer = tlsServer

			go func() {
				g.logger.Info("Starting TLS server", logging.Int("port", tlsPort), logging.String("cert", g.config.Security.TLS.CertFile))
				if err := tlsServer.ListenAndServeTLS(g.config.Security.TLS.CertFile, g.config.Security.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
					g.logger.Error("TLS Server error", err)
				}
			}()
		}
	}

	<-g.shutdown

	g.logger.Info("Shutting down gateway server")
	if g.tlsServer != nil && g.tlsServer != server {
		if err := g.tlsServer.Shutdown(ctx); err != nil {
			g.logger.Error("TLS shutdown error", err)
		}
	}
	if g.http3Server != nil {
		if err := g.http3Server.Shutdown(ctx); err != nil {
			g.logger.Error("HTTP/3 shutdown error", err)
		}
	}
	return server.Shutdown(ctx)
}

// Shutdown gracefully shuts down the gateway.
func (g *Gateway) Shutdown() {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-g.shutdown:
		return
	default:
		close(g.shutdown)
	}

	g.logger.Info("Gateway shutdown complete")
}
