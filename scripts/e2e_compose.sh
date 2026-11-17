#!/usr/bin/env bash
# Local-only end-to-end smoke test: Rust -> Python/FFT -> Go -> PostgreSQL outbox -> Redis Streams.
# Uses a disposable subject and random request UUID; do not point Compose at production services.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "Missing .env; copy .env.example and set local-only secrets first." >&2
  exit 2
fi
set -a
# .env is generated/maintained locally and must contain simple KEY=value entries.
source .env
set +a

sudo docker-compose up -d --build

for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:18080/health >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -fsS http://127.0.0.1:18080/health >/dev/null

# Prove the internal Go route is not exposed to arbitrary callers through the proxy.
unauth_status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/internal/v1/decision -H 'Content-Type: application/json' -d '{}')"
[[ "$unauth_status" == "401" ]] || { echo "Expected internal route 401, got $unauth_status" >&2; exit 1; }

issuer_response="$(curl -fsS -X POST http://127.0.0.1:18080/api/auth/token \
  -H "Authorization: Bearer ${SHADOW_CORE_ISSUER_TOKEN}" -H 'Content-Type: application/json' \
  -d '{"subject":"compose-e2e-synthetic","scopes":["risk:write","risk:analyze","evidence:read","evidence:verify"]}')"
access_token="$(printf '%s' "$issuer_response" | jq -er '.access_token')"
request_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
payload="$(python3 - <<'PY'
import json, math
# 256 evenly spaced samples at 64 Hz; periodic 5 Hz signal, synthetic only.
samples=[math.sin(2*math.pi*5*i/64) for i in range(256)]
print(json.dumps({"fft_samples":samples,"grpc_tls_verified":True},separators=(",",":")))
PY
)"

result="$(curl -fsS -X POST http://127.0.0.1:18080/api/decision \
  -H "Authorization: Bearer ${access_token}" -H 'Content-Type: application/json' \
  -H "Idempotency-Key: ${request_id}" -d "$payload")"
printf '%s' "$result" | jq -e '.fft.detected == true and .fft.dominant_frequency_hz == 5 and .action == "SHORT_TTL" and .session_risk_mode == "high" and .access_ttl_seconds == 20 and .policy_engine == "go-deterministic" and .evidence.event_type == "risk_decision"' >/dev/null || {
  printf 'Unexpected decision result: %s\n' "$result" >&2
  exit 1
}

# Verify durable decision and a versioned Redis event bearing the same request UUID.
pg_row=""
for _ in $(seq 1 30); do
  pg_row="$(sudo docker-compose exec -T postgres psql -U shadow_core -d shadow_core -tAc \
    "SELECT action FROM (SELECT decision->>'action' AS action FROM risk_decisions WHERE request_id='${request_id}'::uuid) d" 2>/dev/null || true)"
  if [[ "$pg_row" == "SHORT_TTL" ]]; then break; fi
  sleep 1
done
[[ "$pg_row" == "SHORT_TTL" ]] || { echo "Decision not found in PostgreSQL for request ${request_id}" >&2; exit 1; }
stream_rows=""
for _ in $(seq 1 30); do
  stream_rows="$(sudo docker-compose exec -T redis redis-cli --raw XREVRANGE shadow:decision-events + - COUNT 50 2>/dev/null || true)"
  if grep -Fq "$request_id" <<<"$stream_rows"; then break; fi
  sleep 1
done
grep -Fq "$request_id" <<<"$stream_rows" || { echo "Outbox event not found in Redis Stream for request ${request_id}" >&2; exit 1; }
grep -Fq 'shadow.decision-event.v1' <<<"$stream_rows" || { echo "Expected versioned event missing from Redis Stream" >&2; exit 1; }

printf 'PASS: Rust proxy auth (401); Python FFT detected synthetic 5 Hz; Go policy SHORT_TTL/20s; PostgreSQL persisted; Redis Streams published versioned event.\n'
printf 'request_id=%s\n' "$request_id"
printf '%s' "$result" | jq '{action, risk_score, policy_version, policy_engine, access_ttl_seconds, fft: {detected: .fft.detected, dominant_frequency_hz: .fft.dominant_frequency_hz}, evidence_id: .evidence.id}'
