package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/graph-gophers/graphql-go"
	"github.com/graph-gophers/graphql-go/relay"
	"github.com/graph-gophers/graphql-transport-ws/graphqlws"
)

type GraphQLProxy struct {
	schema      *graphql.Schema
	resolvers   map[string]interface{}
	mutex       sync.RWMutex
	logger      *Logger
	metrics     *Metrics
	config      *Config
	httpHandler http.Handler
}

func (p *GraphQLProxy) Name() string { return "GraphQLProxy" }

func (p *GraphQLProxy) Initialize(config map[string]interface{}) error {
	// Load schema from file if specified
	if schemaPath, ok := config["schema_path"].(string); ok && schemaPath != "" {
		schemaData, err := ioutil.ReadFile(schemaPath)
		if err != nil {
			return fmt.Errorf("failed to read GraphQL schema: %w", err)
		}
		if err := p.RegisterSchema(string(schemaData)); err != nil {
			return fmt.Errorf("failed to register schema: %w", err)
		}
	}

	// Initialize HTTP handler
	p.httpHandler = p.createHTTPHandler()

	return nil
}

func (p *GraphQLProxy) RegisterSchema(schema string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	opts := []graphql.SchemaOpt{
		graphql.UseFieldResolvers(),
		graphql.MaxDepth(p.config.GraphQLConfig.DepthLimit),
		graphql.MaxParallelism(10),
	}

	s, err := graphql.ParseSchema(schema, p.resolvers, opts...)
	if err != nil {
		return err
	}

	p.schema = s
	return nil
}

func (p *GraphQLProxy) AddResolver(typeName, fieldName string, resolver interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.resolvers[typeName] == nil {
		p.resolvers[typeName] = make(map[string]interface{})
	}

	p.resolvers[typeName].(map[string]interface{})[fieldName] = resolver
	return nil
}

func (p *GraphQLProxy) ExecQuery(ctx context.Context, query string, variables map[string]interface{}, operationName string) (*graphql.Result, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if p.schema == nil {
		return nil, fmt.Errorf("schema not initialized")
	}

	return p.schema.Exec(ctx, query, operationName, variables), nil
}

func (p *GraphQLProxy) ExecRequest(r *http.Request) (*graphql.Result, error) {
	var params struct {
		Query         string                 `json:"query"`
		Variables     map[string]interface{} `json:"variables"`
		OperationName string                 `json:"operationName"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return nil, fmt.Errorf("invalid request body: %w", err)
	}

	return p.ExecQuery(r.Context(), params.Query, params.Variables, params.OperationName)
}

func (p *GraphQLProxy) createHTTPHandler() http.Handler {
	// Standard GraphQL handler
	handler := &relay.Handler{Schema: p.schema}

	// Add WebSocket support for subscriptions
	wsHandler := graphqlws.NewHandlerFunc(p.schema, handler)

	// Add metrics middleware
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Execute query
		result, err := p.ExecRequest(r)
		if err != nil {
			p.logger.Error("GraphQL error: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Record metrics
		duration := time.Since(start)
		p.metrics.ObserveGraphQLQuery(duration, len(result.Errors) > 0)

		// Write response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

func (p *GraphQLProxy) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle GraphQL requests
			if r.URL.Path == "/graphql" {
				p.httpHandler.ServeHTTP(w, r)
				return
			}

			// Handle GraphQL Playground
			if r.URL.Path == "/graphql/playground" && p.config.GraphQLConfig.Playground {
				p.servePlayground(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (p *GraphQLProxy) servePlayground(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>GraphQL Playground</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/css/index.css"/>
            <script src="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/js/middleware.js"></script>
        </head>
        <body>
            <div id="root"></div>
            <script>
                GraphQLPlayground.init(document.getElementById('root'), {
                    endpoint: '/graphql',
                    subscriptionEndpoint: '/graphql',
                    settings: {
                        'request.credentials': 'same-origin'
                    }
                })
            </script>
        </body>
        </html>
    `))
}

func (p *GraphQLProxy) Shutdown() error {
	// Clean up any resources
	return nil
}

var Plugin GraphQLProxy = GraphQLProxy{}
