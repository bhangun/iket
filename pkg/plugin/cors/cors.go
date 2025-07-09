package plugin

import (
	"net/http"
)

type CORSPlugin struct {
	allowOrigin  string
	allowMethods string
}

func (c *CORSPlugin) Name() string { return "cors" }

func (c *CORSPlugin) Init(config map[string]interface{}) error {
	if v, ok := config["allow_origin"].(string); ok {
		c.allowOrigin = v
	} else {
		c.allowOrigin = "*"
	}
	if v, ok := config["allow_methods"].(string); ok {
		c.allowMethods = v
	} else {
		c.allowMethods = "GET,POST,PUT,DELETE,OPTIONS"
	}
	return nil
}

func (c *CORSPlugin) Middleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", c.allowOrigin)
			w.Header().Set("Access-Control-Allow-Methods", c.allowMethods)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
