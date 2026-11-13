package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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
	defer db.ExecContext(context.Background(), "DELETE FROM decision_outbox WHERE request_id=$1::uuid", requestID)
	defer db.ExecContext(context.Background(), "DELETE FROM risk_decisions WHERE request_id=$1::uuid", requestID)
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
