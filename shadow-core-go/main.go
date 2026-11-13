package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	redis "github.com/redis/go-redis/v9"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"
)

const contractVersion = "shadow.risk.v1"

type SignalSet struct {
	FridaDetected         bool `json:"frida_detected"`
	RootIntegrityFailed   bool `json:"root_integrity_failed"`
	JWTValidationFailures int  `json:"jwt_validation_failures"`
	GRPCTLSVerified       bool `json:"grpc_tls_verified"`
	FFTBeaconingDetected  bool `json:"fft_beaconing_detected"`
}

type SignalInput struct {
	FridaDetected         *bool `json:"frida_detected"`
	RootIntegrityFailed   *bool `json:"root_integrity_failed"`
	JWTValidationFailures *int  `json:"jwt_validation_failures"`
	GRPCTLSVerified       *bool `json:"grpc_tls_verified"`
	FFTBeaconingDetected  *bool `json:"fft_beaconing_detected"`
}

func (input SignalInput) value() (SignalSet, error) {
	if input.FridaDetected == nil || input.RootIntegrityFailed == nil || input.JWTValidationFailures == nil ||
		input.GRPCTLSVerified == nil || input.FFTBeaconingDetected == nil {
		return SignalSet{}, errors.New("all signal fields are required")
	}
	return SignalSet{FridaDetected: *input.FridaDetected, RootIntegrityFailed: *input.RootIntegrityFailed,
		JWTValidationFailures: *input.JWTValidationFailures, GRPCTLSVerified: *input.GRPCTLSVerified,
		FFTBeaconingDetected: *input.FFTBeaconingDetected}, nil
}

type DecisionRequest struct {
	RequestID     string          `json:"request_id"`
	Subject       string          `json:"subject"`
	SchemaVersion string          `json:"schema_version"`
	Signals       SignalInput     `json:"signals"`
	Correlation   json.RawMessage `json:"correlation,omitempty"` // audit-only; never an input to policy
}

type Decision struct {
	RiskScore      float64 `json:"risk_score"`
	Action         string  `json:"action"`
	SessionAllowed bool    `json:"session_allowed"`
	PolicyVersion  string  `json:"policy_version"`
	PolicyEngine   string  `json:"policy_engine"`
}

func evaluate(s SignalSet) (Decision, error) {
	if s.JWTValidationFailures < 0 || s.JWTValidationFailures > 100 {
		return Decision{}, errors.New("jwt_validation_failures must be between 0 and 100")
	}
	score := 0.40*boolFloat(s.FridaDetected) +
		0.35*boolFloat(s.RootIntegrityFailed) +
		0.05*float64(min(s.JWTValidationFailures, 5)) +
		0.35*boolFloat(!s.GRPCTLSVerified) +
		0.60*boolFloat(s.FFTBeaconingDetected)
	score = math.Round(math.Min(score, 1.0)*10000) / 10000
	action, allowed := "ALLOW", true
	switch {
	case score >= 0.85:
		action, allowed = "DENY", false
	case score >= 0.60:
		action = "SHORT_TTL"
	case score >= 0.30:
		action = "CHALLENGE"
	}
	return Decision{RiskScore: score, Action: action, SessionAllowed: allowed,
		PolicyVersion: "shadow-policy-2", PolicyEngine: "go-deterministic"}, nil
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func decisionHandler(sharedSecret string, store DecisionRepository, publisher EventPublisher) http.Handler {
	return decisionHandlerWithDispatcher(sharedSecret, &OutboxDispatcher{Store: store, Publisher: publisher})
}

func decisionHandlerWithDispatcher(sharedSecret string, dispatcher *OutboxDispatcher) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "shadow-core-go-policy"})
	})
	mux.HandleFunc("/v1/decision", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		provided := r.Header.Get("X-Shadow-Internal-Token")
		if len(provided) != len(sharedSecret) || subtle.ConstantTimeCompare([]byte(provided), []byte(sharedSecret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var input DecisionRequest
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			http.Error(w, "request must contain one JSON object", http.StatusBadRequest)
			return
		}
		if input.SchemaVersion != contractVersion {
			http.Error(w, "unsupported schema_version", http.StatusBadRequest)
			return
		}
		if _, err := uuid.Parse(input.RequestID); err != nil || strings.TrimSpace(input.Subject) == "" || len(input.Subject) > 200 {
			http.Error(w, "request_id UUID and subject are required", http.StatusBadRequest)
			return
		}
		if len(input.Correlation) > 0 && !json.Valid(input.Correlation) {
			http.Error(w, "invalid correlation metadata", http.StatusBadRequest)
			return
		}
		signals, err := input.Signals.value()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		decision, err := evaluate(signals)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if dispatcher == nil || dispatcher.Store == nil || dispatcher.Publisher == nil {
			http.Error(w, "decision persistence unavailable", http.StatusServiceUnavailable)
			return
		}
		stored, err := dispatcher.Store.Record(r.Context(), input, decision)
		if err != nil {
			if errors.Is(err, ErrIdempotencyConflict) {
				http.Error(w, "idempotency key conflicts with prior request", http.StatusConflict)
				return
			}
			http.Error(w, "decision persistence unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := dispatcher.Flush(r.Context()); err != nil {
			http.Error(w, "decision event delivery unavailable; decision is durably queued", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, stored.Decision)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		client := &http.Client{Timeout: 2 * time.Second}
		response, err := client.Get("http://127.0.0.1:8081/health")
		if err != nil {
			os.Exit(1)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	secret := os.Getenv("SHADOW_GO_INTERNAL_TOKEN")
	if len(secret) < 32 {
		log.Fatal("SHADOW_GO_INTERNAL_TOKEN must be configured with at least 32 characters")
	}
	addr := strings.TrimSpace(os.Getenv("SHADOW_GO_ADDR"))
	if addr == "" {
		addr = ":8081"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := openPostgres(ctx, os.Getenv("SHADOW_POSTGRES_DSN"))
	if err != nil {
		log.Fatalf("PostgreSQL startup failed: %v", err)
	}
	defer db.Close()
	redisURL := strings.TrimSpace(os.Getenv("SHADOW_REDIS_URL"))
	if redisURL == "" {
		log.Fatal("SHADOW_REDIS_URL is required")
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("invalid SHADOW_REDIS_URL: %v", err)
	}
	redisClient := redis.NewClient(options)
	defer redisClient.Close()
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		log.Fatalf("Redis startup failed: %v", err)
	}
	store := PostgresDecisionStore{DB: db}
	publisher := RedisStreamPublisher{Client: redisClient, Stream: os.Getenv("SHADOW_REDIS_STREAM")}
	dispatcher := &OutboxDispatcher{Store: store, Publisher: publisher}
	handler := decisionHandlerWithDispatcher(secret, dispatcher)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	go runOutboxWorker(workerCtx, dispatcher)
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	fmt.Printf("shadow-core-go-policy listening on %s\n", addr)
	log.Fatal(server.ListenAndServe())
}
