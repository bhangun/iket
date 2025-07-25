package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/segmentio/kafka-go"
)

type BillingEvent struct {
	ID           string                 `json:"id"`
	APIKey       string                 `json:"api_key"`
	UserID       string                 `json:"user_id"`
	PlanID       string                 `json:"plan_id"`
	Endpoint     string                 `json:"endpoint"`
	Method       string                 `json:"method"`
	StatusCode   int                    `json:"status_code"`
	RequestSize  int64                  `json:"request_size"`
	ResponseSize int64                  `json:"response_size"`
	Timestamp    time.Time              `json:"timestamp"`
	Cost         float64                `json:"cost"`
	Metadata     map[string]interface{} `json:"metadata"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT/SIGTERM for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("Shutting down billing service...")
		cancel()
	}()

	// Open SQLite DB
	db, err := sql.Open("sqlite3", "billing.db")
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		log.Fatalf("Failed to init DB schema: %v", err)
	}

	// Start REST API for usage queries
	go startAPI(db)

	// Kafka reader config
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{"localhost:9092"},
		Topic:    "billing-events",
		GroupID:  "billing-service",
		MinBytes: 1,
		MaxBytes: 10e6,
	})
	defer reader.Close()

	fmt.Println("Billing service started. Waiting for usage events...")

	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break // graceful shutdown
			}
			log.Printf("Kafka read error: %v", err)
			continue
		}
		var event BillingEvent
		if err := json.Unmarshal(m.Value, &event); err != nil {
			log.Printf("Failed to unmarshal billing event: %v", err)
			continue
		}
		if err := storeEvent(db, &event); err != nil {
			log.Printf("Failed to store billing event: %v", err)
			continue
		}
		fmt.Printf("Stored billing event: %+v\n", event)
	}

	fmt.Println("Billing service stopped.")
}

func initSchema(db *sql.DB) error {
	schema := `CREATE TABLE IF NOT EXISTS billing_events (
		id TEXT PRIMARY KEY,
		api_key TEXT,
		user_id TEXT,
		plan_id TEXT,
		endpoint TEXT,
		method TEXT,
		status_code INTEGER,
		request_size INTEGER,
		response_size INTEGER,
		timestamp DATETIME,
		cost REAL
	);`
	_, err := db.Exec(schema)
	return err
}

func storeEvent(db *sql.DB, e *BillingEvent) error {
	_, err := db.Exec(`INSERT OR IGNORE INTO billing_events (
		id, api_key, user_id, plan_id, endpoint, method, status_code, request_size, response_size, timestamp, cost
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.APIKey, e.UserID, e.PlanID, e.Endpoint, e.Method, e.StatusCode, e.RequestSize, e.ResponseSize, e.Timestamp, e.Cost)
	return err
}

func startAPI(db *sql.DB) {
	http.HandleFunc("/usage", func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.URL.Query().Get("api_key")
		if apiKey == "" {
			http.Error(w, "api_key required", http.StatusBadRequest)
			return
		}
		var totalCost float64
		var requestCount int64
		row := db.QueryRow(`SELECT COALESCE(SUM(cost),0), COUNT(*) FROM billing_events WHERE api_key = ?`, apiKey)
		if err := row.Scan(&totalCost, &requestCount); err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		resp := map[string]interface{}{
			"api_key":       apiKey,
			"total_cost":    totalCost,
			"request_count": requestCount,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// /usage/user?user_id=...
	http.HandleFunc("/usage/user", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			http.Error(w, "user_id required", http.StatusBadRequest)
			return
		}
		var totalCost float64
		var requestCount int64
		row := db.QueryRow(`SELECT COALESCE(SUM(cost),0), COUNT(*) FROM billing_events WHERE user_id = ?`, userID)
		if err := row.Scan(&totalCost, &requestCount); err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		resp := map[string]interface{}{
			"user_id":       userID,
			"total_cost":    totalCost,
			"request_count": requestCount,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// /usage/plan?plan_id=...
	http.HandleFunc("/usage/plan", func(w http.ResponseWriter, r *http.Request) {
		planID := r.URL.Query().Get("plan_id")
		if planID == "" {
			http.Error(w, "plan_id required", http.StatusBadRequest)
			return
		}
		var totalCost float64
		var requestCount int64
		row := db.QueryRow(`SELECT COALESCE(SUM(cost),0), COUNT(*) FROM billing_events WHERE plan_id = ?`, planID)
		if err := row.Scan(&totalCost, &requestCount); err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		resp := map[string]interface{}{
			"plan_id":       planID,
			"total_cost":    totalCost,
			"request_count": requestCount,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// /usage/daily?api_key=... (daily breakdown)
	http.HandleFunc("/usage/daily", func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.URL.Query().Get("api_key")
		if apiKey == "" {
			http.Error(w, "api_key required", http.StatusBadRequest)
			return
		}
		rows, err := db.Query(`SELECT DATE(timestamp), COUNT(*), SUM(cost) FROM billing_events WHERE api_key = ? GROUP BY DATE(timestamp) ORDER BY DATE(timestamp) DESC LIMIT 30`, apiKey)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var days []map[string]interface{}
		for rows.Next() {
			var date string
			var count int64
			var cost float64
			if err := rows.Scan(&date, &count, &cost); err != nil {
				continue
			}
			days = append(days, map[string]interface{}{
				"date":          date,
				"request_count": count,
				"total_cost":    cost,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(days)
	})

	// /usage/top_endpoints?api_key=... (top endpoints by cost)
	http.HandleFunc("/usage/top_endpoints", func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.URL.Query().Get("api_key")
		if apiKey == "" {
			http.Error(w, "api_key required", http.StatusBadRequest)
			return
		}
		rows, err := db.Query(`SELECT endpoint, method, COUNT(*), SUM(cost) FROM billing_events WHERE api_key = ? GROUP BY endpoint, method ORDER BY SUM(cost) DESC LIMIT 10`, apiKey)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var endpoints []map[string]interface{}
		for rows.Next() {
			var endpoint, method string
			var count int64
			var cost float64
			if err := rows.Scan(&endpoint, &method, &count, &cost); err != nil {
				continue
			}
			endpoints = append(endpoints, map[string]interface{}{
				"endpoint":      endpoint,
				"method":        method,
				"request_count": count,
				"total_cost":    cost,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(endpoints)
	})

	log.Println("REST API listening on :8080 (/usage, /usage/user, /usage/plan, /usage/daily, /usage/top_endpoints)")
	http.ListenAndServe(":8080", nil)
}
