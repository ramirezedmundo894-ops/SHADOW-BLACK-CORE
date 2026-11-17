#!/usr/bin/env bash
# Controlled local-only recovery check: queue a durable outbox row while the actual
# Compose Redis container is stopped, restart Redis, and verify the Go worker publishes it.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "Missing .env; this test requires the local Compose environment." >&2
  exit 2
fi
set -a
source .env
set +a

compose=(sudo docker-compose)
redis_was_stopped=0
request_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
stream="shadow:decision-events"
event_id=""
stream_entry_id=""

cleanup() {
  rc=$?
  trap - EXIT
  set +e
  if [[ "$redis_was_stopped" == "1" ]]; then
    "${compose[@]}" start redis >/dev/null 2>&1
    for _ in $(seq 1 30); do
      if "${compose[@]}" exec -T redis redis-cli ping 2>/dev/null | grep -qx PONG; then break; fi
      sleep 1
    done
  fi
  if [[ -n "$stream_entry_id" ]]; then
    "${compose[@]}" exec -T redis redis-cli XDEL "$stream" "$stream_entry_id" >/dev/null 2>&1
  fi
  if [[ -n "$request_id" ]]; then
    "${compose[@]}" exec -T postgres psql -U shadow_core -d shadow_core -v ON_ERROR_STOP=1 -c \
      "DELETE FROM decision_outbox WHERE request_id='${request_id}'::uuid; DELETE FROM risk_decisions WHERE request_id='${request_id}'::uuid;" >/dev/null 2>&1
  fi
  exit "$rc"
}
trap cleanup EXIT

# Never target a non-local Compose configuration; the committed development manifest
# must publish only loopback addresses before this test stops any service.
if ! "${compose[@]}" config | grep -Fq '127.0.0.1:16379:6379'; then
  echo "Refusing: Compose Redis port is not bound to loopback as expected." >&2
  exit 2
fi
if ! "${compose[@]}" ps redis | grep -q 'Up'; then
  echo "Redis must already be running in the local Compose stack." >&2
  exit 2
fi

"${compose[@]}" stop redis >/dev/null
redis_was_stopped=1
payload="{\"request_id\":\"${request_id}\",\"subject\":\"compose-redis-restart-test\",\"schema_version\":\"shadow.risk.v1\",\"signals\":{\"frida_detected\":false,\"root_integrity_failed\":false,\"jwt_validation_failures\":0,\"grpc_tls_verified\":true,\"fft_beaconing_detected\":true},\"correlation\":{\"source\":\"local-container-restart-test\"}}"
status="$(curl -sS --max-time 8 -o /tmp/shadow-redis-restart-response -w '%{http_code}' \
  -X POST http://127.0.0.1:18080/internal/v1/decision \
  -H "Authorization: Bearer ${SHADOW_GO_PROXY_TOKEN}" -H 'Content-Type: application/json' -d "$payload")"
[[ "$status" == "503" ]] || { echo "Expected HTTP 503 while Redis is stopped; got $status" >&2; exit 1; }

row=""
for _ in $(seq 1 20); do
  row="$("${compose[@]}" exec -T postgres psql -U shadow_core -d shadow_core -tAc \
    "SELECT d.decision->>'action' || '|' || (o.published_at IS NULL)::text FROM risk_decisions d JOIN decision_outbox o USING (request_id) WHERE d.request_id='${request_id}'::uuid" 2>/dev/null || true)"
  if [[ "$row" == "SHORT_TTL|true" ]]; then break; fi
  sleep 1
done
[[ "$row" == "SHORT_TTL|true" ]] || { echo "Decision was not durably queued as expected: ${row:-no row}" >&2; exit 1; }

"${compose[@]}" start redis >/dev/null
redis_was_stopped=0
for _ in $(seq 1 30); do
  if "${compose[@]}" exec -T redis redis-cli ping 2>/dev/null | grep -qx PONG; then break; fi
  sleep 1
done
"${compose[@]}" exec -T redis redis-cli ping | grep -qx PONG || { echo "Redis did not become healthy after restart." >&2; exit 1; }

stream_state=""
for _ in $(seq 1 30); do
  stream_state="$("${compose[@]}" exec -T redis redis-cli --json XRANGE "$stream" - + 2>/dev/null | \
    REQUEST_ID="$request_id" python3 -c 'import json,os,sys; rows=json.load(sys.stdin); matches=[(i,dict(zip(v[::2],v[1::2]))) for i,v in rows if dict(zip(v[::2],v[1::2])).get("request_id")==os.environ["REQUEST_ID"]]; print("|".join([str(len(matches))]+[i+":"+f["event_id"] for i,f in matches]))' 2>/dev/null || true)"
  event_id="$("${compose[@]}" exec -T postgres psql -U shadow_core -d shadow_core -tAc \
    "SELECT event_id::text FROM decision_outbox WHERE request_id='${request_id}'::uuid AND published_at IS NOT NULL" 2>/dev/null | tr -d '\r' || true)"
  if [[ "$stream_state" == "1|"* && -n "$event_id" ]]; then break; fi
  sleep 1
done
[[ "$stream_state" == "1|"* ]] || { echo "Expected one Redis event for test request; got ${stream_state:-none}" >&2; exit 1; }
stream_entry_id="${stream_state#1|}"
stream_entry_id="${stream_entry_id%%:*}"
stream_event_id="${stream_state#*:}"
[[ "$stream_event_id" == "$event_id" ]] || { echo "Redis event ID did not match the published PostgreSQL outbox row." >&2; exit 1; }

printf 'PASS: actual Redis container stop/start; pending PostgreSQL outbox recovered by Go worker; one event_id=%s for request %s.\n' "$event_id" "$request_id"
printf 'Cleanup removes only this generated request UUID and its verified Redis stream entry.\n'
