package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	redis "github.com/redis/go-redis/v9"
)

// These integration tests are opt-in and should point only at disposable local services.
// The PostgreSQL test inserts and deletes only UUIDs it generated itself.
func TestPostgresDecisionStoreIdempotencyAndOutbox(t *testing.T) {
	dsn := os.Getenv("SHADOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SHADOW_TEST_POSTGRES_DSN to an isolated disposable test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := PostgresDecisionStore{DB: db}
	requestID := uuid.NewString()
	falseVal, trueVal, zero := false, true, 0
	req := DecisionRequest{RequestID: requestID, Subject: "integration-test", SchemaVersion: contractVersion,
		Signals:     SignalInput{FridaDetected: &falseVal, RootIntegrityFailed: &falseVal, JWTValidationFailures: &zero, GRPCTLSVerified: &trueVal, FFTBeaconingDetected: &trueVal},
		Correlation: json.RawMessage(`{"source":"test-only"}`)}
	decision, err := evaluate(SignalSet{GRPCTLSVerified: true, FFTBeaconingDetected: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Record(ctx, req, decision)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), "DELETE FROM risk_decisions WHERE request_id=$1::uuid", requestID)
	defer db.ExecContext(context.Background(), "DELETE FROM decision_outbox WHERE request_id=$1::uuid", requestID)
	second, err := store.Record(ctx, req, decision)
	if err != nil {
		t.Fatal(err)
	}
	if first.Event.EventID != second.Event.EventID || first.Decision.Action != second.Decision.Action {
		t.Fatalf("idempotent retry changed stored result: first=%+v second=%+v", first, second)
	}
	changed := req
	changed.Signals = SignalInput{FridaDetected: &trueVal, RootIntegrityFailed: &falseVal, JWTValidationFailures: &zero, GRPCTLSVerified: &trueVal, FFTBeaconingDetected: &trueVal}
	if _, err := store.Record(ctx, changed, decision); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	pending, err := store.Pending(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range pending {
		if event.EventID == first.Event.EventID {
			found = true
		}
	}
	if !found {
		t.Fatalf("new decision missing from durable outbox: %+v", pending)
	}
	if err := store.MarkPublished(ctx, first.Event.EventID); err != nil {
		t.Fatal(err)
	}
	pending, err = store.Pending(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range pending {
		if event.EventID == first.Event.EventID {
			t.Fatal("published event remained pending")
		}
	}
}

func TestRedisStreamPublisherWritesVersionedEvent(t *testing.T) {
	url := os.Getenv("SHADOW_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set SHADOW_TEST_REDIS_URL to an isolated disposable local Redis")
	}
	options, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	stream := "shadow:test:" + uuid.NewString()
	defer client.Del(context.Background(), stream)
	eventID, requestID := uuid.NewString(), uuid.NewString()
	event := OutboxEvent{EventID: eventID, RequestID: requestID, SchemaVersion: decisionEventSchema, Payload: json.RawMessage(`{"event_id":"` + eventID + `","schema_version":"` + decisionEventSchema + `"}`)}
	if err := (RedisStreamPublisher{Client: client, Stream: stream}).Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	entries, err := client.XRange(ctx, stream, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Values["event_id"] != eventID || entries[0].Values["request_id"] != requestID || entries[0].Values["schema_version"] != decisionEventSchema {
		t.Fatalf("unexpected stream entry: %+v", entries)
	}
}

// Keep a compile-time reference to pgx's database/sql driver in this test package.
var _ = stdlib.GetDefaultDriver

// This test exercises recovery across a Go store/dispatcher restart. It requires only
// disposable local PostgreSQL and Redis; it creates one UUID row and one unique stream.
func TestOutboxRetrySurvivesStoreRestartAndRedisUnavailable(t *testing.T) {
	dsn := os.Getenv("SHADOW_TEST_POSTGRES_DSN")
	redisURL := os.Getenv("SHADOW_TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("set SHADOW_TEST_POSTGRES_DSN and SHADOW_TEST_REDIS_URL to isolated disposable local services")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	store := PostgresDecisionStore{DB: db}
	falseVal, trueVal, zero := false, true, 0
	req := DecisionRequest{
		RequestID: uuid.NewString(), Subject: "restart-recovery-test", SchemaVersion: contractVersion,
		Signals:     SignalInput{FridaDetected: &falseVal, RootIntegrityFailed: &falseVal, JWTValidationFailures: &zero, GRPCTLSVerified: &trueVal, FFTBeaconingDetected: &trueVal},
		Correlation: json.RawMessage(`{"source":"restart-recovery-test"}`),
	}
	decision, err := evaluate(SignalSet{GRPCTLSVerified: true, FFTBeaconingDetected: true})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	stored, err := store.Record(ctx, req, decision)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	// Cleanup is scoped to this freshly generated request UUID. The harness also drops
	// its disposable database after the test run.
	defer func() {
		if db != nil {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM decision_outbox WHERE request_id=$1::uuid`, req.RequestID)
			_, _ = db.ExecContext(context.Background(), `DELETE FROM risk_decisions WHERE request_id=$1::uuid`, req.RequestID)
			_ = db.Close()
		}
	}()

	stream := "shadow:restart-test:" + uuid.NewString()
	defer func() {
		options, parseErr := redis.ParseURL(redisURL)
		if parseErr == nil {
			client := redis.NewClient(options)
			_ = client.Del(context.Background(), stream).Err()
			_ = client.Close()
		}
	}()

	// Simulate Redis being unreachable. The durable outbox must remain pending.
	unavailableRedis := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond, WriteTimeout: 100 * time.Millisecond, MaxRetries: 0})
	if err := (&OutboxDispatcher{Store: store, Publisher: RedisStreamPublisher{Client: unavailableRedis, Stream: stream}}).Flush(ctx); err == nil {
		_ = unavailableRedis.Close()
		db.Close()
		t.Fatal("expected Redis-unavailable delivery failure")
	}
	_ = unavailableRedis.Close()
	pending, err := store.Pending(ctx, 100)
	if err != nil || len(pending) != 1 || pending[0].EventID != stored.Event.EventID {
		db.Close()
		t.Fatalf("outbox event was not retained after Redis failure: pending=%+v err=%v", pending, err)
	}

	// Drop the original DB handle to model service restart, then recover from persisted outbox.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	recoveredStore := PostgresDecisionStore{DB: db}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	defer client.Close()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	recovered := &OutboxDispatcher{Store: recoveredStore, Publisher: RedisStreamPublisher{Client: client, Stream: stream}}
	if err := recovered.Flush(ctx); err != nil {
		t.Fatalf("outbox recovery after store restart failed: %v", err)
	}
	entries, err := client.XRange(ctx, stream, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Values["event_id"] != stored.Event.EventID {
		t.Fatalf("recovery did not publish the persisted event once: %+v", entries)
	}
	pending, err = recoveredStore.Pending(ctx, 100)
	if err != nil || len(pending) != 0 {
		t.Fatalf("recovered event remains pending: pending=%+v err=%v", pending, err)
	}
}

type failOnceMarkStore struct {
	DecisionRepository
	fail bool
}

func (s *failOnceMarkStore) MarkPublished(ctx context.Context, eventID string) error {
	if s.fail {
		s.fail = false
		return errors.New("simulated crash after Redis accepted XADD")
	}
	return s.DecisionRepository.MarkPublished(ctx, eventID)
}

// This verifies the documented at-least-once edge with actual PostgreSQL and Redis:
// XADD succeeds, marking the outbox row fails, then restart/retry publishes the same ID again.
func TestRedisAtLeastOnceDuplicateKeepsStableEventID(t *testing.T) {
	dsn := os.Getenv("SHADOW_TEST_POSTGRES_DSN")
	redisURL := os.Getenv("SHADOW_TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("set SHADOW_TEST_POSTGRES_DSN and SHADOW_TEST_REDIS_URL to isolated disposable local services")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := PostgresDecisionStore{DB: db}
	falseVal, trueVal, zero := false, true, 0
	req := DecisionRequest{
		RequestID: uuid.NewString(), Subject: "at-least-once-test", SchemaVersion: contractVersion,
		Signals:     SignalInput{FridaDetected: &falseVal, RootIntegrityFailed: &falseVal, JWTValidationFailures: &zero, GRPCTLSVerified: &trueVal, FFTBeaconingDetected: &trueVal},
		Correlation: json.RawMessage(`{"source":"at-least-once-test"}`),
	}
	decision, err := evaluate(SignalSet{GRPCTLSVerified: true, FFTBeaconingDetected: true})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := base.Record(ctx, req, decision)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM risk_decisions WHERE request_id=$1::uuid`, req.RequestID)
	defer db.ExecContext(context.Background(), `DELETE FROM decision_outbox WHERE request_id=$1::uuid`, req.RequestID)

	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	defer client.Close()
	stream := "shadow:at-least-once-test:" + uuid.NewString()
	defer client.Del(context.Background(), stream)
	wrapped := &failOnceMarkStore{DecisionRepository: base, fail: true}
	if err := (&OutboxDispatcher{Store: wrapped, Publisher: RedisStreamPublisher{Client: client, Stream: stream}}).Flush(ctx); err == nil {
		t.Fatal("expected injected mark-published failure")
	}
	if count, err := client.XLen(ctx, stream).Result(); err != nil || count != 1 {
		t.Fatalf("expected first XADD to be accepted, length=%d err=%v", count, err)
	}
	if err := (&OutboxDispatcher{Store: base, Publisher: RedisStreamPublisher{Client: client, Stream: stream}}).Flush(ctx); err != nil {
		t.Fatalf("retry after simulated process restart failed: %v", err)
	}
	entries, err := client.XRange(ctx, stream, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Values["event_id"] != stored.Event.EventID || entries[1].Values["event_id"] != stored.Event.EventID {
		t.Fatalf("expected two deliveries with same stable event ID %q, got %+v", stored.Event.EventID, entries)
	}
	pending, err := base.Pending(ctx, 100)
	if err != nil || len(pending) != 0 {
		t.Fatalf("event remains pending after retry: pending=%+v err=%v", pending, err)
	}
}

// Concurrent HTTP retries with the same idempotency key should return the same stored
// decision and create one decision/outbox record. This opts in only with local test services.
func TestConcurrentDecisionRequestsAreIdempotent(t *testing.T) {
	dsn := os.Getenv("SHADOW_TEST_POSTGRES_DSN")
	redisURL := os.Getenv("SHADOW_TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("set SHADOW_TEST_POSTGRES_DSN and SHADOW_TEST_REDIS_URL to local test services")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	defer client.Close()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	stream := "shadow:concurrent-idempotency-test:" + uuid.NewString()
	defer client.Del(context.Background(), stream)

	requestID := uuid.NewString()
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM decision_outbox WHERE request_id=$1::uuid`, requestID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM risk_decisions WHERE request_id=$1::uuid`, requestID)
	}()
	falseVal, trueVal, zero := false, true, 0
	req := DecisionRequest{
		RequestID: requestID, Subject: "concurrent-idempotency-test", SchemaVersion: contractVersion,
		Signals: SignalInput{FridaDetected: &falseVal, RootIntegrityFailed: &falseVal,
			JWTValidationFailures: &zero, GRPCTLSVerified: &trueVal, FFTBeaconingDetected: &trueVal},
		Correlation: json.RawMessage(`{"source":"concurrent-idempotency-test"}`),
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	start := make(chan struct{})
	type result struct {
		status int
		err    error
	}
	results := make(chan result, workers)
	var wg sync.WaitGroup
	store := PostgresDecisionStore{DB: db}
	handler := decisionHandler("local-integration-test-secret", store, RedisStreamPublisher{Client: client, Stream: stream})
	server := httptest.NewServer(handler)
	defer server.Close()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/decision", bytes.NewReader(body))
			if err != nil {
				results <- result{err: err}
				return
			}
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("X-Shadow-Internal-Token", "local-integration-test-secret")
			response, err := http.DefaultClient.Do(httpReq)
			if err != nil {
				results <- result{err: err}
				return
			}
			_ = response.Body.Close()
			results <- result{status: response.StatusCode}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for result := range results {
		if result.err != nil {
			t.Errorf("concurrent decision request failed: %v", result.err)
		} else if result.status != http.StatusOK {
			t.Errorf("concurrent idempotent retry returned HTTP %d, want 200", result.status)
		}
	}

	var decisions, outbox int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM risk_decisions WHERE request_id=$1::uuid`, requestID).Scan(&decisions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM decision_outbox WHERE request_id=$1::uuid`, requestID).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if decisions != 1 || outbox != 1 {
		t.Fatalf("want one durable decision and one outbox event; decisions=%d outbox=%d", decisions, outbox)
	}
	entries, err := client.XRange(ctx, stream, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Values["request_id"] != requestID {
		t.Fatalf("want one Redis event for request %s, got %+v", requestID, entries)
	}
}
