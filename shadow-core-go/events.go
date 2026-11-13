package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type EventPublisher interface {
	Publish(context.Context, OutboxEvent) error
}

type RedisStreamPublisher struct {
	Client *redis.Client
	Stream string
}

func (p RedisStreamPublisher) Publish(ctx context.Context, event OutboxEvent) error {
	if p.Client == nil {
		return errors.New("Redis client is not configured")
	}
	stream := p.Stream
	if stream == "" {
		stream = "shadow:decision-events"
	}
	// At-least-once transport: event_id is stable and consumers must dedupe it.
	// PostgreSQL's outbox is authoritative; Redis is only the delivery stream.
	_, err := p.Client.XAdd(ctx, &redis.XAddArgs{
		Stream: stream, Values: map[string]any{
			"event_id":       event.EventID,
			"request_id":     event.RequestID,
			"schema_version": event.SchemaVersion,
			"payload":        string(event.Payload),
		},
	}).Result()
	return err
}

func marshalEventPayload(event OutboxEvent) ([]byte, error) {
	return json.Marshal(event)
}

type OutboxDispatcher struct {
	Store     DecisionRepository
	Publisher EventPublisher
	mu        sync.Mutex
}

func (d *OutboxDispatcher) Flush(ctx context.Context) error {
	if d == nil || d.Store == nil || d.Publisher == nil {
		return errors.New("outbox store and publisher are required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	events, err := d.Store.Pending(ctx, 100)
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := d.Publisher.Publish(ctx, event); err != nil {
			return err
		}
		if err := d.Store.MarkPublished(ctx, event.EventID); err != nil {
			return err
		}
	}
	return nil
}

func runOutboxWorker(ctx context.Context, dispatcher *OutboxDispatcher) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flushCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			_ = dispatcher.Flush(flushCtx)
			cancel()
		}
	}
}
