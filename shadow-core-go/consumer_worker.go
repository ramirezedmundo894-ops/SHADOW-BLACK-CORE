package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
)

const defaultDecisionEventStream = "shadow:decision-events"

// DecisionEventStreamWorker reads a Redis consumer group and ACKs only after the
// inbox transaction and its database effect have committed. If the process stops
// between commit and ACK, a replay is harmless because the inbox is authoritative.
type DecisionEventStreamWorker struct {
	Client       *redis.Client
	Inbox        DecisionEventConsumer
	Stream       string
	Group        string
	ConsumerName string
	Apply        func(context.Context, *sql.Tx, OutboxEvent) error

	block        time.Duration
	claimMinIdle time.Duration
	claimEvery   time.Duration
}

func (w *DecisionEventStreamWorker) Run(ctx context.Context) error {
	if w == nil || w.Client == nil {
		return errors.New("Redis client is required")
	}
	if w.Inbox.DB == nil || strings.TrimSpace(w.Inbox.Name) == "" {
		return errors.New("PostgreSQL inbox and logical consumer name are required")
	}
	if strings.TrimSpace(w.Group) == "" || len(w.Group) > 120 {
		return errors.New("Redis consumer group must contain 1 to 120 characters")
	}
	if strings.TrimSpace(w.ConsumerName) == "" || len(w.ConsumerName) > 120 {
		return errors.New("Redis consumer name must contain 1 to 120 characters")
	}
	if w.Apply == nil {
		return errors.New("transactional event handler is required")
	}
	if w.Stream == "" {
		w.Stream = defaultDecisionEventStream
	}
	block := w.block
	if block <= 0 {
		block = time.Second
	}
	claimMinIdle := w.claimMinIdle
	if claimMinIdle <= 0 {
		claimMinIdle = 30 * time.Second
	}
	claimEvery := w.claimEvery
	if claimEvery <= 0 {
		claimEvery = 5 * time.Second
	}

	if err := w.ensureGroup(ctx); err != nil {
		return fmt.Errorf("create Redis consumer group: %w", err)
	}
	log.Printf("decision event consumer started: stream=%s group=%s consumer=%s", w.Stream, w.Group, w.ConsumerName)

	claimCursor := "0-0"
	nextClaim := time.Time{}
	for ctx.Err() == nil {
		if !time.Now().Before(nextClaim) {
			messages, next, err := w.Client.XAutoClaim(ctx, &redis.XAutoClaimArgs{
				Stream: w.Stream, Group: w.Group, Consumer: w.ConsumerName,
				MinIdle: claimMinIdle, Start: claimCursor, Count: 16,
			}).Result()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("claim pending Redis events: %w", err)
			}
			for _, message := range messages {
				w.processAndAck(ctx, message)
			}
			if next == "0-0" {
				claimCursor = "0-0"
				nextClaim = time.Now().Add(claimEvery)
			} else {
				claimCursor = next
				nextClaim = time.Now()
			}
		}

		streams, err := w.Client.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group: w.Group, Consumer: w.ConsumerName,
			Streams: []string{w.Stream, ">"}, Count: 16, Block: block,
		}).Result()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, redis.Nil) {
				continue
			}
			return fmt.Errorf("read Redis decision events: %w", err)
		}
		for _, stream := range streams {
			for _, message := range stream.Messages {
				w.processAndAck(ctx, message)
			}
		}
	}
	return nil
}

func (w *DecisionEventStreamWorker) ensureGroup(ctx context.Context) error {
	stream := w.Stream
	if stream == "" {
		stream = defaultDecisionEventStream
	}
	err := w.Client.XGroupCreateMkStream(ctx, stream, w.Group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

func (w *DecisionEventStreamWorker) processAndAck(ctx context.Context, message redis.XMessage) {
	event, err := decisionEventFromStreamMessage(message)
	if err == nil {
		_, err = w.Inbox.Process(ctx, event, w.Apply)
	}
	if err != nil {
		log.Printf("decision event remains pending: stream=%s group=%s message=%s err=%v", w.Stream, w.Group, message.ID, err)
		return
	}
	if err := w.Client.XAck(ctx, w.Stream, w.Group, message.ID).Err(); err != nil {
		log.Printf("decision event committed but ACK failed; replay is safe: stream=%s group=%s message=%s err=%v", w.Stream, w.Group, message.ID, err)
	}
}

func decisionEventFromStreamMessage(message redis.XMessage) (OutboxEvent, error) {
	field := func(name string) (string, error) {
		value, ok := message.Values[name]
		if !ok {
			return "", fmt.Errorf("Redis event %s is missing %q", message.ID, name)
		}
		switch typed := value.(type) {
		case string:
			return typed, nil
		case []byte:
			return string(typed), nil
		default:
			return "", fmt.Errorf("Redis event %s field %q has unsupported type %T", message.ID, name, value)
		}
	}
	eventID, err := field("event_id")
	if err != nil {
		return OutboxEvent{}, err
	}
	requestID, err := field("request_id")
	if err != nil {
		return OutboxEvent{}, err
	}
	schemaVersion, err := field("schema_version")
	if err != nil {
		return OutboxEvent{}, err
	}
	payload, err := field("payload")
	if err != nil {
		return OutboxEvent{}, err
	}
	if !json.Valid([]byte(payload)) {
		return OutboxEvent{}, fmt.Errorf("Redis event %s payload is not valid JSON", message.ID)
	}
	return OutboxEvent{
		EventID: eventID, RequestID: requestID, SchemaVersion: schemaVersion,
		Payload: json.RawMessage(payload),
	}, nil
}

func saveDecisionEventProjection(consumerName string) func(context.Context, *sql.Tx, OutboxEvent) error {
	return func(ctx context.Context, tx *sql.Tx, event OutboxEvent) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO decision_event_projection
			(consumer_name, event_id, request_id, schema_version, payload)
			VALUES ($1, $2::uuid, $3::uuid, $4, $5::jsonb)`,
			consumerName, event.EventID, event.RequestID, event.SchemaVersion, string(event.Payload))
		return err
	}
}

func runDecisionEventWorker(ctx context.Context, worker *DecisionEventStreamWorker) {
	for ctx.Err() == nil {
		if err := worker.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("decision event consumer stopped; retrying: %v", err)
		}
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}
