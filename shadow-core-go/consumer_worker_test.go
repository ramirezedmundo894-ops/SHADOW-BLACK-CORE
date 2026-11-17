package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	redis "github.com/redis/go-redis/v9"
)

func TestDecisionEventFromStreamMessage(t *testing.T) {
	eventID, requestID := uuid.NewString(), uuid.NewString()
	payload := fmt.Sprintf(`{"event_id":%q,"request_id":%q,"schema_version":%q}`, eventID, requestID, decisionEventSchema)
	event, err := decisionEventFromStreamMessage(redis.XMessage{ID: "1-0", Values: map[string]interface{}{
		"event_id": eventID, "request_id": []byte(requestID),
		"schema_version": decisionEventSchema, "payload": payload,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if event.EventID != eventID || event.RequestID != requestID || event.SchemaVersion != decisionEventSchema || string(event.Payload) != payload {
		t.Fatalf("decoded event does not match fields: %+v", event)
	}

	if _, err := decisionEventFromStreamMessage(redis.XMessage{ID: "2-0", Values: map[string]interface{}{"event_id": eventID}}); err == nil {
		t.Fatal("expected missing stream fields to be rejected")
	}
	if _, err := decisionEventFromStreamMessage(redis.XMessage{ID: "3-0", Values: map[string]interface{}{
		"event_id": eventID, "request_id": requestID, "schema_version": decisionEventSchema, "payload": "not-json",
	}}); err == nil {
		t.Fatal("expected invalid JSON payload to be rejected")
	}
}

// This integration test requires disposable PostgreSQL and Redis instances.
// It verifies transaction-before-ACK, retry of a failed effect, and idempotent
// handling of a duplicate stream delivery through a real consumer group.
func TestRedisDecisionEventWorkerRetriesAndDeduplicates(t *testing.T) {
	dsn, redisURL := os.Getenv("SHADOW_TEST_POSTGRES_DSN"), os.Getenv("SHADOW_TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("set SHADOW_TEST_POSTGRES_DSN and SHADOW_TEST_REDIS_URL to isolated disposable services")
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

	suffix := uuid.NewString()
	stream, group := "shadow:consumer-test:"+suffix, "consumer-test:"+suffix
	workerName := "worker:" + suffix
	eventID, requestID := uuid.NewString(), uuid.NewString()
	event := makeDecisionEvent(eventID, requestID)
	worker := &DecisionEventStreamWorker{
		Client: client, Inbox: DecisionEventConsumer{DB: db, Name: group},
		Stream: stream, Group: group, ConsumerName: workerName,
		claimMinIdle: 10 * time.Millisecond, claimEvery: 10 * time.Millisecond, block: 10 * time.Millisecond,
	}
	if err := worker.ensureGroup(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM decision_event_projection WHERE consumer_name=$1 AND event_id=$2::uuid`, group, eventID)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM decision_consumer_inbox WHERE consumer_name=$1 AND event_id=$2::uuid`, group, eventID)
		_ = client.XGroupDestroy(cleanupCtx, stream, group).Err()
		_ = client.Del(cleanupCtx, stream).Err()
	}()

	var handlerCalls int32
	persist := saveDecisionEventProjection(group)
	worker.Apply = func(ctx context.Context, tx *sql.Tx, event OutboxEvent) error {
		call := atomic.AddInt32(&handlerCalls, 1)
		if err := persist(ctx, tx, event); err != nil {
			return err
		}
		if call == 1 {
			return errors.New("injected effect failure before transaction commit")
		}
		return nil
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() { workerDone <- worker.Run(workerCtx) }()
	defer func() {
		stopWorker()
		select {
		case err := <-workerDone:
			if err != nil {
				t.Errorf("worker exited with error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("worker did not stop after context cancellation")
		}
	}()

	if err := (RedisStreamPublisher{Client: client, Stream: stream}).Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, ctx, "first event retry and ACK", func() (bool, error) {
		var projections int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM decision_event_projection WHERE consumer_name=$1 AND event_id=$2::uuid`, group, eventID).Scan(&projections); err != nil {
			return false, err
		}
		pending, err := client.XPending(ctx, stream, group).Result()
		if err != nil {
			return false, err
		}
		return projections == 1 && pending.Count == 0 && atomic.LoadInt32(&handlerCalls) == 2, nil
	})

	// A second Redis entry for the same logical event must be ACKed as a replay,
	// without running the downstream SQL effect again.
	if err := (RedisStreamPublisher{Client: client, Stream: stream}).Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, ctx, "duplicate delivery ACK", func() (bool, error) {
		pending, err := client.XPending(ctx, stream, group).Result()
		if err != nil {
			return false, err
		}
		length, err := client.XLen(ctx, stream).Result()
		if err != nil {
			return false, err
		}
		var inboxRows, projections int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM decision_consumer_inbox WHERE consumer_name=$1 AND event_id=$2::uuid`, group, eventID).Scan(&inboxRows); err != nil {
			return false, err
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM decision_event_projection WHERE consumer_name=$1 AND event_id=$2::uuid`, group, eventID).Scan(&projections); err != nil {
			return false, err
		}
		return length == 2 && pending.Count == 0 && inboxRows == 1 && projections == 1 && atomic.LoadInt32(&handlerCalls) == 2, nil
	})
}

func waitUntil(t *testing.T, ctx context.Context, description string, condition func() (bool, error)) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready, err := condition()
		if err != nil {
			t.Fatalf("checking %s: %v", description, err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s: %v", description, ctx.Err())
		case <-ticker.C:
		}
	}
}
