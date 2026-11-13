package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const testSecret = "unit-test-secret-that-is-long-enough-123456"

type memoryRepository struct {
	mu      sync.Mutex
	rows    map[string]StoredDecision
	pending []OutboxEvent
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{rows: map[string]StoredDecision{}}
}
func (m *memoryRepository) Record(_ context.Context, req DecisionRequest, decision Decision) (StoredDecision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prior, ok := m.rows[req.RequestID]; ok {
		if prior.Event.Payload != nil && prior.Event.RequestID == req.RequestID {
			return prior, nil
		}
	}
	payload, _ := json.Marshal(map[string]any{"request_id": req.RequestID, "subject": req.Subject, "schema_version": decisionEventSchema, "decision": decision})
	event := OutboxEvent{EventID: "00000000-0000-4000-8000-000000000001", RequestID: req.RequestID, SchemaVersion: decisionEventSchema, Payload: payload, CreatedAt: time.Now()}
	stored := StoredDecision{Decision: decision, Event: event}
	m.rows[req.RequestID] = stored
	m.pending = append(m.pending, event)
	return stored, nil
}
func (m *memoryRepository) Pending(_ context.Context, limit int) ([]OutboxEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit > len(m.pending) {
		limit = len(m.pending)
	}
	return append([]OutboxEvent(nil), m.pending[:limit]...), nil
}
func (m *memoryRepository) MarkPublished(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.pending {
		if e.EventID == id {
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			break
		}
	}
	return nil
}

type memoryPublisher struct {
	events []OutboxEvent
	fail   bool
}

func (m *memoryPublisher) Publish(_ context.Context, e OutboxEvent) error {
	if m.fail {
		return errors.New("redis down")
	}
	m.events = append(m.events, e)
	return nil
}

func testHandler(repo *memoryRepository, pub *memoryPublisher) http.Handler {
	return decisionHandler(testSecret, repo, pub)
}
func validPayload(correlation string) []byte {
	return []byte(`{"request_id":"00000000-0000-4000-8000-000000000002","subject":"test-user","schema_version":"shadow.risk.v1","signals":{"frida_detected":false,"root_integrity_failed":false,"jwt_validation_failures":0,"grpc_tls_verified":true,"fft_beaconing_detected":true}` + correlation + `}`)
}
func request(handler http.Handler, payload []byte, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewReader(payload))
	if token != "" {
		req.Header.Set("X-Shadow-Internal-Token", token)
	}
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func TestFFTSignalDrivesDeterministicShortTTL(t *testing.T) {
	decision, err := evaluate(SignalSet{GRPCTLSVerified: true, FFTBeaconingDetected: true})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RiskScore != 0.6 || decision.Action != "SHORT_TTL" || !decision.SessionAllowed {
		t.Fatalf("unexpected FFT policy decision: %+v", decision)
	}
	if decision.PolicyEngine != "go-deterministic" {
		t.Fatalf("unexpected policy engine: %s", decision.PolicyEngine)
	}
}
func TestPolicyCapsScoreAndDeniesHighRisk(t *testing.T) {
	decision, err := evaluate(SignalSet{FridaDetected: true, RootIntegrityFailed: true, JWTValidationFailures: 5, GRPCTLSVerified: false, FFTBeaconingDetected: true})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RiskScore != 1 || decision.Action != "DENY" || decision.SessionAllowed {
		t.Fatalf("unexpected deny decision: %+v", decision)
	}
}
func TestHTTPContractRequiresTokenAndStrictSchema(t *testing.T) {
	repo, pub := newMemoryRepository(), &memoryPublisher{}
	handler := testHandler(repo, pub)
	payload := validPayload("")
	if got := request(handler, payload, "").Code; got != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", got)
	}
	response := request(handler, payload, testSecret)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var got Decision
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Action != "SHORT_TTL" || got.PolicyEngine != "go-deterministic" {
		t.Fatalf("unexpected response: %+v", got)
	}
	if len(pub.events) != 1 || pub.events[0].SchemaVersion != decisionEventSchema {
		t.Fatalf("event not versioned/published: %+v", pub.events)
	}
	bad := []byte(`{"request_id":"00000000-0000-4000-8000-000000000002","subject":"test-user","schema_version":"shadow.risk.v1","signals":{"frida_detected":false,"root_integrity_failed":false,"jwt_validation_failures":0,"grpc_tls_verified":true,"fft_beaconing_detected":true},"risk_score":1}`)
	if code := request(handler, bad, testSecret).Code; code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", code)
	}
}
func TestCorrelationMetadataCannotChangeDecision(t *testing.T) {
	decision := func(c string) *httptest.ResponseRecorder {
		repo, pub := newMemoryRepository(), &memoryPublisher{}
		return request(testHandler(repo, pub), validPayload(`,"correlation":`+c), testSecret)
	}
	a, b := decision(`{"score":0}`), decision(`{"score":1,"used_for_decision":true}`)
	if a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Fatalf("correlation metadata changed decision: %s vs %s", a.Body.String(), b.Body.String())
	}
}
func TestBadSchemaAndOutOfRangeSignalsRejected(t *testing.T) {
	for _, payload := range []string{
		`{"request_id":"00000000-0000-4000-8000-000000000002","subject":"x","schema_version":"shadow.risk.v0","signals":{"frida_detected":false,"root_integrity_failed":false,"jwt_validation_failures":0,"grpc_tls_verified":true,"fft_beaconing_detected":false}}`,
		`{"request_id":"00000000-0000-4000-8000-000000000002","subject":"x","schema_version":"shadow.risk.v1","signals":{"frida_detected":false}}`,
		`{"request_id":"00000000-0000-4000-8000-000000000002","subject":"x","schema_version":"shadow.risk.v1","signals":{"frida_detected":false,"root_integrity_failed":false,"jwt_validation_failures":101,"grpc_tls_verified":true,"fft_beaconing_detected":false}}`,
	} {
		repo, pub := newMemoryRepository(), &memoryPublisher{}
		if code := request(testHandler(repo, pub), []byte(payload), testSecret).Code; code != http.StatusBadRequest {
			t.Fatalf("expected 400; got %d", code)
		}
	}
}
func TestPersistenceAndRedisFailuresFailClosed(t *testing.T) {
	repo, pub := newMemoryRepository(), &memoryPublisher{fail: true}
	response := request(testHandler(repo, pub), validPayload(""), testSecret)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected fail-closed 503, got %d", response.Code)
	}
	if len(repo.pending) != 1 {
		t.Fatalf("failed delivery lost durable outbox event: %+v", repo.pending)
	}
	pub.fail = false
	response = request(testHandler(repo, pub), validPayload(""), testSecret)
	if response.Code != http.StatusOK {
		t.Fatalf("outbox retry did not recover: %d %s", response.Code, response.Body.String())
	}
}
func TestMissingPersistenceFailsClosed(t *testing.T) {
	h := decisionHandler(testSecret, nil, nil)
	if code := request(h, validPayload(""), testSecret).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", code)
	}
}
