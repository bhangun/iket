package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/graph-gophers/graphql-go"
	"github.com/graph-gophers/graphql-go/relay"
)

// Resolver interface for GraphQL resolvers
type Resolver interface {
	Query() interface{}
	Mutation() interface{}
}

type GraphQLPlugin struct {
	schema      *graphql.Schema
	resolvers   map[string]interface{}
	mutex       sync.RWMutex
	httpHandler http.Handler
}

func (p *GraphQLPlugin) Name() string { return "GraphQLPlugin" }

func (p *GraphQLPlugin) Initialize(config map[string]interface{}) error {
	p.resolvers = make(map[string]interface{})

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

func (p *GraphQLPlugin) RegisterSchema(schemaStr string) error {
	schema, err := graphql.ParseSchema(schemaStr, p)
	if err != nil {
		return fmt.Errorf("failed to parse schema: %w", err)
	}

	p.schema = schema
	return nil
}

func (p *GraphQLPlugin) RegisterResolver(name string, resolver interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.resolvers[name] = resolver
	return nil
}

func (p *GraphQLPlugin) createHTTPHandler() http.Handler {
	if p.schema == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "GraphQL schema not initialized", http.StatusInternalServerError)
		})
	}

	return &relay.Handler{Schema: p.schema}
}

func (p *GraphQLPlugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.httpHandler.ServeHTTP(w, r)
}

// Query implements the Resolver interface
func (p *GraphQLPlugin) Query() interface{} {
	return p.resolvers["Query"]
}

// Mutation implements the Resolver interface
func (p *GraphQLPlugin) Mutation() interface{} {
	return p.resolvers["Mutation"]
}

func (p *GraphQLPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle GraphQL requests
			if r.URL.Path == "/graphql" {
				p.ServeHTTP(w, r)
				return
			}
			// Pass other requests to the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// Export plugin
var Plugin GraphQLPlugin
