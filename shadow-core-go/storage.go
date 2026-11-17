package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"database/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const decisionEventSchema = "shadow.decision-event.v1"

var ErrIdempotencyConflict = errors.New("idempotency key was already used with different request data")

type DecisionRepository interface {
	Record(context.Context, DecisionRequest, Decision) (StoredDecision, error)
	Pending(context.Context, int) ([]OutboxEvent, error)
	MarkPublished(context.Context, string) error
}

type StoredDecision struct {
	Decision Decision
	Event    OutboxEvent
}

type OutboxEvent struct {
	EventID       string          `json:"event_id"`
	RequestID     string          `json:"request_id"`
	SchemaVersion string          `json:"schema_version"`
	Payload       json.RawMessage `json:"payload"`
	CreatedAt     time.Time       `json:"created_at"`
}

func openPostgres(ctx context.Context, dsn string) (*sql.DB, error) {
	if dsn == "" {
		return nil, errors.New("SHADOW_POSTGRES_DSN is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, err
	}
	if err := migratePostgres(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migratePostgres(ctx context.Context, db *sql.DB) error {
	// Serialize the bootstrap as well as versioned migrations. The ledger must
	// not be created concurrently by two replicas on a fresh database.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(78234719504001)`); err != nil {
		return fmt.Errorf("lock schema migrations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, entry := range entries { // embed.FS returns directory entries sorted by name.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version := strings.TrimSuffix(entry.Name(), ".sql")
		migration, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		var applied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied {
			continue
		}
		// Migrations contain plain SQL statements, so split them to avoid pgx's
		// prepared-statement restrictions on multi-command SQL strings.
		for _, statement := range strings.Split(string(migration), ";") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply migration %s: %w", version, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, version); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

type PostgresDecisionStore struct{ DB *sql.DB }

func (s PostgresDecisionStore) Record(ctx context.Context, req DecisionRequest, decision Decision) (StoredDecision, error) {
	requestBytes, err := json.Marshal(struct {
		Schema      string          `json:"schema_version"`
		Subject     string          `json:"subject"`
		Signals     SignalInput     `json:"signals"`
		Correlation json.RawMessage `json:"correlation,omitempty"`
	}{req.SchemaVersion, req.Subject, req.Signals, req.Correlation})
	if err != nil {
		return StoredDecision{}, err
	}
	digest := sha256.Sum256(requestBytes)
	decisionJSON, err := json.Marshal(decision)
	if err != nil {
		return StoredDecision{}, err
	}

	// The unique request_id index serializes competing inserts; READ COMMITTED
	// then exposes the winning row to the follow-up read after ON CONFLICT waits.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return StoredDecision{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO risk_decisions
		(request_id, subject, schema_version, request_fingerprint, decision)
		VALUES ($1::uuid, $2, $3, $4, $5::jsonb) ON CONFLICT (request_id) DO NOTHING`,
		req.RequestID, req.Subject, req.SchemaVersion, digest[:], string(decisionJSON))
	if err != nil {
		return StoredDecision{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return StoredDecision{}, err
	}

	var storedDigest []byte
	var storedDecision []byte
	if inserted == 0 {
		if err := tx.QueryRowContext(ctx, `SELECT request_fingerprint, decision FROM risk_decisions WHERE request_id=$1::uuid`, req.RequestID).Scan(&storedDigest, &storedDecision); err != nil {
			return StoredDecision{}, err
		}
		if !equalBytes(storedDigest, digest[:]) {
			return StoredDecision{}, ErrIdempotencyConflict
		}
		if err := json.Unmarshal(storedDecision, &decision); err != nil {
			return StoredDecision{}, err
		}
	}
	var event OutboxEvent
	var payload []byte
	if inserted == 1 {
		eventID := uuid.NewString()
		// The event id is stable in PostgreSQL and travels with at-least-once delivery;
		// consumers must deduplicate it if a crash occurs after XADD.
		payload, err = json.Marshal(map[string]any{
			"event_id": eventID, "request_id": req.RequestID,
			"schema_version": decisionEventSchema, "subject": req.Subject,
			"signals": req.Signals, "correlation": req.Correlation, "decision": decision,
		})
		if err != nil {
			return StoredDecision{}, err
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO decision_outbox
			(event_id, request_id, schema_version, payload)
			VALUES ($1::uuid, $2::uuid, $3, $4::jsonb) RETURNING created_at`,
			eventID, req.RequestID, decisionEventSchema, string(payload)).Scan(&event.CreatedAt); err != nil {
			return StoredDecision{}, err
		}
		event = OutboxEvent{EventID: eventID, RequestID: req.RequestID, SchemaVersion: decisionEventSchema, Payload: payload, CreatedAt: event.CreatedAt}
	} else {
		var createdAt time.Time
		if err := tx.QueryRowContext(ctx, `SELECT event_id::text, request_id::text, schema_version, payload, created_at
			FROM decision_outbox WHERE request_id=$1::uuid`, req.RequestID).Scan(&event.EventID, &event.RequestID, &event.SchemaVersion, &event.Payload, &createdAt); err != nil {
			return StoredDecision{}, err
		}
		event.CreatedAt = createdAt
	}
	if err := tx.Commit(); err != nil {
		return StoredDecision{}, err
	}
	return StoredDecision{Decision: decision, Event: event}, nil
}

func (s PostgresDecisionStore) Pending(ctx context.Context, limit int) ([]OutboxEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("outbox limit must be between 1 and 1000")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT event_id::text, request_id::text, schema_version, payload, created_at
		FROM decision_outbox WHERE published_at IS NULL ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []OutboxEvent
	for rows.Next() {
		var event OutboxEvent
		if err := rows.Scan(&event.EventID, &event.RequestID, &event.SchemaVersion, &event.Payload, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s PostgresDecisionStore) MarkPublished(ctx context.Context, eventID string) error {
	if _, err := uuid.Parse(eventID); err != nil {
		return fmt.Errorf("invalid event id: %w", err)
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE decision_outbox SET published_at=now() WHERE event_id=$1::uuid AND published_at IS NULL`, eventID)
	return err
}

func equalBytes(a, b []byte) bool {
	return bytes.Equal(a, b)
}
