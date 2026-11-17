#!/usr/bin/env bash
# Isolated local-only restart check. Creates a unique Compose project and named
# volumes, then destroys only that project. Never uses the developer's existing
# Compose volumes or host SQLite database.
set -euo pipefail
cd "$(dirname "$0")/.."

[[ -f .env ]] || { echo "Missing local .env; refusing to launch." >&2; exit 2; }
set -a
source .env
set +a
: "${SHADOW_POSTGRES_PASSWORD:?set SHADOW_POSTGRES_PASSWORD in local .env}"
: "${SHADOW_GO_INTERNAL_TOKEN:?set SHADOW_GO_INTERNAL_TOKEN in local .env}"
: "${SHADOW_REDIS_STREAM:=shadow:decision-events}"

compose_bin=(sudo docker-compose)
project="shadow-restart-test-$(date +%s)-$$"
tmpdir="$(mktemp -d /tmp/shadow-compose-restart.XXXXXX)"
compose_test_file=".compose.restart-test-${project}.yaml"
started=0
cleanup() {
  if [[ "$started" == 1 ]]; then
    "${compose_bin[@]}" -p "$project" -f "$compose_test_file" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f "$compose_test_file"
  rm -rf "$tmpdir"
}
trap cleanup EXIT

# Choose currently free host ports; bind only to loopback. These mappings are
# confined to this disposable Compose project.
read -r pg_port redis_port go_port < <(python3 - <<'PY'
import socket
ports=[]
for _ in range(3):
    s=socket.socket(); s.bind(('127.0.0.1',0)); ports.append(s.getsockname()[1]); s.close()
print(*ports)
PY
)
# Make a temporary full Compose file so the fixed developer ports in the
# base manifest are replaced, not merged with additional mappings by v1.
sed \
  -e "s#127.0.0.1:54329:5432#127.0.0.1:${pg_port}:5432#" \
  -e "s#127.0.0.1:16379:6379#127.0.0.1:${redis_port}:6379#" \
  -e "s#127.0.0.1:18081:8081#127.0.0.1:${go_port}:8081#" \
  compose.yaml > "$compose_test_file"

"${compose_bin[@]}" -p "$project" -f "$compose_test_file" config >/dev/null
# Mark cleanup active before `up`: it can create some resources and still fail.
started=1
"${compose_bin[@]}" -p "$project" -f "$compose_test_file" up -d --build postgres redis go-policy

wait_go() {
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${go_port}/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "Go health endpoint did not recover on 127.0.0.1:${go_port}." >&2
  "${compose_bin[@]}" -p "$project" -f "$compose_test_file" ps >&2 || true
  "${compose_bin[@]}" -p "$project" -f "$compose_test_file" logs --tail=80 postgres redis go-policy >&2 || true
  return 1
}
wait_pg() {
  for _ in $(seq 1 60); do
    if "${compose_bin[@]}" -p "$project" -f "$compose_test_file" exec -T postgres pg_isready -U shadow_core -d shadow_core >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "PostgreSQL did not become ready." >&2
  return 1
}
pg() {
  "${compose_bin[@]}" -p "$project" -f "$compose_test_file" exec -T postgres psql -U shadow_core -d shadow_core -tAc "$1" | tr -d '\r'
}
post_decision() {
  local request_id="$1"
  local payload
  payload="$(printf '{"request_id":"%s","subject":"disposable-restart-test","schema_version":"shadow.risk.v1","signals":{"frida_detected":false,"root_integrity_failed":false,"jwt_validation_failures":0,"grpc_tls_verified":true,"fft_beaconing_detected":false},"correlation":{"source":"disposable-restart-test"}}' "$request_id")"
  curl -sS --max-time 10 -o "$tmpdir/response.json" -w '%{http_code}' \
    -X POST "http://127.0.0.1:${go_port}/v1/decision" \
    -H "X-Shadow-Internal-Token: ${SHADOW_GO_INTERNAL_TOKEN}" \
    -H 'Content-Type: application/json' --data "$payload"
}
wait_pg
wait_go

# One successful decision is committed before the PostgreSQL container restart.
pg_request="$(python3 -c 'import uuid; print(uuid.uuid4())')"
status="$(post_decision "$pg_request")"
[[ "$status" == 200 ]] || { echo "Initial decision returned HTTP $status." >&2; exit 1; }
"${compose_bin[@]}" -p "$project" -f "$compose_test_file" restart postgres >/dev/null
wait_pg
pg_result=""
for _ in $(seq 1 20); do
  pg_result="$(pg "SELECT d.decision->>'action' || '|' || (o.published_at IS NOT NULL)::text FROM risk_decisions d JOIN decision_outbox o USING (request_id) WHERE d.request_id='${pg_request}'::uuid" 2>/dev/null || true)"
  [[ "$pg_result" == "ALLOW|true" ]] && break
  sleep 1
done
[[ "$pg_result" == "ALLOW|true" ]] || { echo "PostgreSQL restart did not retain the committed decision/outbox: $pg_result" >&2; exit 1; }

# A Go process restart must reconnect to the same disposable PostgreSQL/Redis services.
go_request="$(python3 -c 'import uuid; print(uuid.uuid4())')"
status="$(post_decision "$go_request")"
[[ "$status" == 200 ]] || { echo "Pre-Go-restart decision returned HTTP $status." >&2; exit 1; }
"${compose_bin[@]}" -p "$project" -f "$compose_test_file" restart go-policy >/dev/null
wait_go
go_result="$(pg "SELECT d.decision->>'action' FROM risk_decisions d WHERE d.request_id='${go_request}'::uuid")"
[[ "$go_result" == "ALLOW" ]] || { echo "Go restart lost its persisted decision: $go_result" >&2; exit 1; }

# Stop the disposable Redis container, queue an outbox event, restart Go while
# Redis is unavailable, and confirm both service health and recovery after Redis returns.
"${compose_bin[@]}" -p "$project" -f "$compose_test_file" stop redis >/dev/null
pending_request="$(python3 -c 'import uuid; print(uuid.uuid4())')"
status="$(post_decision "$pending_request")"
[[ "$status" == 503 ]] || { echo "Expected 503 while Redis was stopped, got HTTP $status." >&2; exit 1; }
pending="$(pg "SELECT count(*) FROM decision_outbox WHERE request_id='${pending_request}'::uuid AND published_at IS NULL")"
[[ "$pending" == 1 ]] || { echo "Pending PostgreSQL outbox was not retained; count=$pending" >&2; exit 1; }
"${compose_bin[@]}" -p "$project" -f "$compose_test_file" restart go-policy >/dev/null
wait_go
"${compose_bin[@]}" -p "$project" -f "$compose_test_file" start redis >/dev/null
published=""
for _ in $(seq 1 60); do
  published="$(pg "SELECT count(*) FROM decision_outbox WHERE request_id='${pending_request}'::uuid AND published_at IS NOT NULL" 2>/dev/null || true)"
  [[ "$published" == 1 ]] && break
  sleep 1
done
[[ "$published" == 1 ]] || { echo "Pending outbox was not published after Redis restart." >&2; exit 1; }
event_id="$(pg "SELECT event_id::text FROM decision_outbox WHERE request_id='${pending_request}'::uuid")"
stream_entries="$("${compose_bin[@]}" -p "$project" -f "$compose_test_file" exec -T redis redis-cli --json XRANGE "$SHADOW_REDIS_STREAM" - +)"
stream_count="$(printf '%s\n' "$stream_entries" | python3 -c '
import json, sys
wanted = sys.argv[1]
entries = json.load(sys.stdin)
print(sum(1 for entry in entries if dict(zip(entry[1][::2], entry[1][1::2])).get("event_id") == wanted))
' "$event_id")"
[[ "$stream_count" == 1 ]] || { echo "Expected one stream entry with event_id=$event_id, saw $stream_count." >&2; exit 1; }

printf 'PASS: disposable project %s; PostgreSQL container restart retained committed row; Go process restart reconnected; pending outbox recovered after Redis outage/restart; event_id=%s.\n' "$project" "$event_id"
printf 'Ports were loopback-only: postgres=%s redis=%s go=%s. Cleanup removes only this project and its fresh volumes.\n' "$pg_port" "$redis_port" "$go_port"
