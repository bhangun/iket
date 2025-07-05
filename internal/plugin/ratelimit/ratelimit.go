package plugin

import (
	"net/http"

	"golang.org/x/time/rate"
)

type RateLimitPlugin struct {
	limiter *rate.Limiter
}

func (p *RateLimitPlugin) Name() string { return "rate_limit" }

func (p *RateLimitPlugin) Init(config map[string]interface{}) error {
	var rps float64 = 1
	var burst int = 5
	if v, ok := config["requests_per_second"].(float64); ok {
		rps = v
	} else if v, ok := config["requests_per_second"].(int); ok {
		rps = float64(v)
	}
	if v, ok := config["burst"].(int); ok {
		burst = v
	} else if v, ok := config["burst"].(float64); ok {
		burst = int(v)
	}
	p.limiter = rate.NewLimiter(rate.Limit(rps), burst)
	return nil
}

func (p *RateLimitPlugin) Middleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !p.limiter.Allow() {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"Too Many Requests","message":"Rate limit exceeded"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
