package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

var ErrEventConflict = errors.New("event id was already processed with different content")

// DecisionEventConsumer stores an inbox row and applies the consumer's database
// effect in one PostgreSQL transaction. A Redis consumer should acknowledge its
// stream entry only after Process returns without error. Effects outside this
// transaction are not made exactly-once by this helper.
type DecisionEventConsumer struct {
	DB   *sql.DB
	Name string
}

// Process returns true when this event was applied now and false for an identical
// replay. Reusing an event ID with different metadata or payload is rejected.
func (c DecisionEventConsumer) Process(
	ctx context.Context,
	event OutboxEvent,
	apply func(context.Context, *sql.Tx, OutboxEvent) error,
) (bool, error) {
	if c.DB == nil {
		return false, errors.New("consumer database is required")
	}
	consumerName := strings.TrimSpace(c.Name)
	if consumerName == "" || len(consumerName) > 120 {
		return false, errors.New("consumer name must contain 1 to 120 characters")
	}
	if apply == nil {
		return false, errors.New("transactional event handler is required")
	}
	eventID, requestID, payload, err := validateDecisionEvent(event)
	if err != nil {
		return false, err
	}
	fingerprint := eventFingerprint(requestID, event.SchemaVersion, payload)

	tx, err := c.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `INSERT INTO decision_consumer_inbox
		(consumer_name, event_id, request_id, schema_version, payload_sha256)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5)
		ON CONFLICT (consumer_name, event_id) DO NOTHING`,
		consumerName, eventID.String(), requestID.String(), event.SchemaVersion, fingerprint[:])
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if inserted == 0 {
		var storedRequestID, storedSchema string
		var storedFingerprint []byte
		err := tx.QueryRowContext(ctx, `SELECT request_id::text, schema_version, payload_sha256
			FROM decision_consumer_inbox WHERE consumer_name=$1 AND event_id=$2::uuid`,
			consumerName, eventID.String()).Scan(&storedRequestID, &storedSchema, &storedFingerprint)
		if err != nil {
			return false, err
		}
		if storedRequestID != requestID.String() || storedSchema != event.SchemaVersion ||
			!equalBytes(storedFingerprint, fingerprint[:]) {
			return false, ErrEventConflict
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}

	if err := apply(ctx, tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func validateDecisionEvent(event OutboxEvent) (uuid.UUID, uuid.UUID, []byte, error) {
	eventID, err := uuid.Parse(event.EventID)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, fmt.Errorf("invalid event id: %w", err)
	}
	requestID, err := uuid.Parse(event.RequestID)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, fmt.Errorf("invalid request id: %w", err)
	}
	if event.SchemaVersion != decisionEventSchema {
		return uuid.Nil, uuid.Nil, nil, fmt.Errorf("unsupported decision event schema %q", event.SchemaVersion)
	}
	if !json.Valid(event.Payload) {
		return uuid.Nil, uuid.Nil, nil, errors.New("event payload must be valid JSON")
	}
	var envelope struct {
		EventID       string `json:"event_id"`
		RequestID     string `json:"request_id"`
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(event.Payload, &envelope); err != nil {
		return uuid.Nil, uuid.Nil, nil, errors.New("event payload must be a JSON object")
	}
	payloadEventID, err := uuid.Parse(envelope.EventID)
	if err != nil || payloadEventID != eventID {
		return uuid.Nil, uuid.Nil, nil, errors.New("event id does not match payload")
	}
	payloadRequestID, err := uuid.Parse(envelope.RequestID)
	if err != nil || payloadRequestID != requestID {
		return uuid.Nil, uuid.Nil, nil, errors.New("request id does not match payload")
	}
	if envelope.SchemaVersion != event.SchemaVersion {
		return uuid.Nil, uuid.Nil, nil, errors.New("schema version does not match payload")
	}

	// Compact JSON and deterministic map-key ordering make insignificant whitespace
	// or object-key ordering differences equivalent while keeping value changes visible.
	var decoded any
	decoder := json.NewDecoder(strings.NewReader(string(event.Payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return uuid.Nil, uuid.Nil, nil, errors.New("event payload could not be decoded")
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, errors.New("event payload could not be canonicalized")
	}
	return eventID, requestID, canonical, nil
}

func eventFingerprint(requestID uuid.UUID, schema string, payload []byte) [32]byte {
	material := make([]byte, 0, len(requestID)+len(schema)+len(payload)+2)
	material = append(material, requestID.String()...)
	material = append(material, 0)
	material = append(material, schema...)
	material = append(material, 0)
	material = append(material, payload...)
	return sha256.Sum256(material)
}
