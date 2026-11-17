package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func makeDecisionEvent(eventID, requestID string) OutboxEvent {
	payload, _ := json.Marshal(map[string]any{
		"event_id": eventID, "request_id": requestID,
		"schema_version": decisionEventSchema,
		"subject":        "consumer-test",
		"decision":       map[string]any{"action": "SHORT_TTL", "risk_score": 0.6},
	})
	return OutboxEvent{
		EventID: eventID, RequestID: requestID,
		SchemaVersion: decisionEventSchema, Payload: payload,
	}
}

func TestValidateDecisionEventChecksEnvelopeAndCanonicalizesJSON(t *testing.T) {
	eventID, requestID := uuid.NewString(), uuid.NewString()
	event := makeDecisionEvent(eventID, requestID)
	parsedEventID, parsedRequestID, first, err := validateDecisionEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if parsedEventID.String() != eventID || parsedRequestID.String() != requestID {
		t.Fatalf("unexpected parsed ids: event=%s request=%s", parsedEventID, parsedRequestID)
	}

	// JSON object key order and insignificant whitespace do not change the digest.
	event.Payload = json.RawMessage(fmt.Sprintf(`{ "decision":{"risk_score":0.6,"action":"SHORT_TTL"},"subject":"consumer-test","schema_version":%q,"request_id":%q,"event_id":%q }`, decisionEventSchema, requestID, eventID))
	_, _, second, err := validateDecisionEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("equivalent JSON did not canonicalize identically:\n%s\n%s", first, second)
	}

	bad := event
	bad.Payload = json.RawMessage(fmt.Sprintf(`{"event_id":%q,"request_id":%q,"schema_version":%q}`, uuid.NewString(), requestID, decisionEventSchema))
	if _, _, _, err := validateDecisionEvent(bad); err == nil {
		t.Fatal("expected mismatched envelope event ID to be rejected")
	}
}

// This integration test requires only a disposable local PostgreSQL database.
// It verifies the inbox and a consumer side effect commit atomically under replay
// from multiple consumer instances.
func TestDecisionEventConsumerConcurrentReplayIsIdempotent(t *testing.T) {
	dsn := os.Getenv("SHADOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SHADOW_TEST_POSTGRES_DSN to an isolated disposable test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS decision_consumer_test_effects (
		run_id UUID NOT NULL, event_id UUID NOT NULL, value TEXT NOT NULL,
		PRIMARY KEY (run_id, event_id)
	)`); err != nil {
		t.Fatal(err)
	}

	runID, eventID, requestID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	consumerName := "integration-test:" + runID
	event := makeDecisionEvent(eventID, requestID)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM decision_consumer_test_effects WHERE run_id=$1::uuid`, runID)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM decision_consumer_inbox WHERE consumer_name=$1 AND event_id=$2::uuid`, consumerName, eventID)
	})

	const workers = 24
	start := make(chan struct{})
	type result struct {
		processed bool
		err       error
	}
	results := make(chan result, workers)
	var applied int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			consumer := DecisionEventConsumer{DB: db, Name: consumerName}
			processed, err := consumer.Process(ctx, event, func(ctx context.Context, tx *sql.Tx, event OutboxEvent) error {
				atomic.AddInt32(&applied, 1)
				_, err := tx.ExecContext(ctx, `INSERT INTO decision_consumer_test_effects(run_id,event_id,value)
					VALUES($1::uuid,$2::uuid,$3)`, runID, event.EventID, "handled")
				return err
			})
			results <- result{processed: processed, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	newlyProcessed := 0
	for result := range results {
		if result.err != nil {
			t.Errorf("processing replay failed: %v", result.err)
		}
		if result.processed {
			newlyProcessed++
		}
	}
	if newlyProcessed != 1 || atomic.LoadInt32(&applied) != 1 {
		t.Fatalf("want exactly one committed application; processed=%d callback_calls=%d", newlyProcessed, atomic.LoadInt32(&applied))
	}
	var inboxRows, effectRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM decision_consumer_inbox WHERE consumer_name=$1 AND event_id=$2::uuid`, consumerName, eventID).Scan(&inboxRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM decision_consumer_test_effects WHERE run_id=$1::uuid AND event_id=$2::uuid`, runID, eventID).Scan(&effectRows); err != nil {
		t.Fatal(err)
	}
	if inboxRows != 1 || effectRows != 1 {
		t.Fatalf("want one inbox row and one side effect; inbox=%d effects=%d", inboxRows, effectRows)
	}

	// Reusing the stable ID with altered content is not an idempotent replay.
	conflict := event
	conflict.Payload = json.RawMessage(fmt.Sprintf(`{"event_id":%q,"request_id":%q,"schema_version":%q,"subject":"changed","decision":{"action":"ALLOW"}}`, eventID, requestID, decisionEventSchema))
	if _, err := (DecisionEventConsumer{DB: db, Name: consumerName}).Process(ctx, conflict, func(context.Context, *sql.Tx, OutboxEvent) error {
		t.Error("conflicting replay must not reach the handler")
		return nil
	}); !errors.Is(err, ErrEventConflict) {
		t.Fatalf("want ErrEventConflict for changed payload, got %v", err)
	}
}

func TestDecisionEventConsumerRollsBackFailedEffect(t *testing.T) {
	dsn := os.Getenv("SHADOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SHADOW_TEST_POSTGRES_DSN to an isolated disposable test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS decision_consumer_test_effects (
		run_id UUID NOT NULL, event_id UUID NOT NULL, value TEXT NOT NULL,
		PRIMARY KEY (run_id, event_id)
	)`); err != nil {
		t.Fatal(err)
	}

	runID, eventID, requestID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	consumerName := "rollback-test:" + runID
	event := makeDecisionEvent(eventID, requestID)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM decision_consumer_test_effects WHERE run_id=$1::uuid`, runID)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM decision_consumer_inbox WHERE consumer_name=$1 AND event_id=$2::uuid`, consumerName, eventID)
	})
	consumer := DecisionEventConsumer{DB: db, Name: consumerName}
	failed := errors.New("simulated downstream write failure")
	if processed, err := consumer.Process(ctx, event, func(ctx context.Context, tx *sql.Tx, event OutboxEvent) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO decision_consumer_test_effects(run_id,event_id,value)
			VALUES($1::uuid,$2::uuid,$3)`, runID, event.EventID, "must-rollback"); err != nil {
			return err
		}
		return failed
	}); processed || !errors.Is(err, failed) {
		t.Fatalf("expected handler failure to abort, processed=%v err=%v", processed, err)
	}
	var inboxRows, effectRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM decision_consumer_inbox WHERE consumer_name=$1 AND event_id=$2::uuid`, consumerName, eventID).Scan(&inboxRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM decision_consumer_test_effects WHERE run_id=$1::uuid AND event_id=$2::uuid`, runID, eventID).Scan(&effectRows); err != nil {
		t.Fatal(err)
	}
	if inboxRows != 0 || effectRows != 0 {
		t.Fatalf("failed handler must roll back inbox and effect; inbox=%d effects=%d", inboxRows, effectRows)
	}
	processed, err := consumer.Process(ctx, event, func(ctx context.Context, tx *sql.Tx, event OutboxEvent) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO decision_consumer_test_effects(run_id,event_id,value)
			VALUES($1::uuid,$2::uuid,$3)`, runID, event.EventID, "retried")
		return err
	})
	if err != nil || !processed {
		t.Fatalf("valid retry after rollback failed: processed=%v err=%v", processed, err)
	}
}
