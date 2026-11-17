#!/usr/bin/env bash
# Disposable two-process idempotency check. Uses fresh Compose volumes and
# loopback-only host ports; never touches the main project or local SQLite.
set -euo pipefail
cd "$(dirname "$0")/.."

[[ -f .env ]] || { echo "Missing local .env; refusing to launch." >&2; exit 2; }

sqlite_file="$PWD/data/shadow-core.sqlite3"
[[ -f "$sqlite_file" ]] || { echo "Expected local SQLite fingerprint file is missing; refusing to run." >&2; exit 2; }
sqlite_size_before="$(stat -c '%s' "$sqlite_file")"
sqlite_hash_before="$(sha256sum "$sqlite_file" | awk '{print $1}')"

compose_bin=(sudo docker-compose)
project="shadow-multireplica-test-$(date +%s)-$$"
tmpdir="$(mktemp -d /tmp/shadow-compose-multireplica.XXXXXX)"
compose_test_file=".compose.multireplica-test-${project}.yaml"
started=0
cleanup() {
  local result=$?
  if [[ "$started" == 1 ]]; then
    "${compose_bin[@]}" -p "$project" -f "$compose_test_file" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f "$compose_test_file"
  rm -rf "$tmpdir"
  if [[ ! -f "$sqlite_file" ]]; then
    echo "Local SQLite disappeared during the isolated test." >&2
    result=1
  else
    local size_after hash_after
    size_after="$(stat -c '%s' "$sqlite_file")"
    hash_after="$(sha256sum "$sqlite_file" | awk '{print $1}')"
    if [[ "$size_after" != "$sqlite_size_before" || "$hash_after" != "$sqlite_hash_before" ]]; then
      echo "Local SQLite fingerprint changed during the test." >&2
      result=1
    fi
  fi
  exit "$result"
}
trap cleanup EXIT

# Hold sockets open until all distinct loopback ports have been selected.
read -r pg_port redis_port go_one_port go_two_port < <(python3 - <<'PY'
import socket
sockets = []
ports = []
for _ in range(4):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
    ports.append(sock.getsockname()[1])
print(*ports)
for sock in sockets:
    sock.close()
PY
)

python3 - "$compose_test_file" "$pg_port" "$redis_port" "$go_one_port" "$go_two_port" "$project" <<'PY'
from pathlib import Path
import sys

target = Path(sys.argv[1])
pg_port, redis_port, go_one_port, go_two_port = sys.argv[2:6]
project = sys.argv[6]
text = Path("compose.yaml").read_text()
for old, new in (
    ("127.0.0.1:54329:5432", f"127.0.0.1:{pg_port}:5432"),
    ("127.0.0.1:16379:6379", f"127.0.0.1:{redis_port}:6379"),
    ("127.0.0.1:18081:8081", f"127.0.0.1:{go_one_port}:8081"),
    ("      SHADOW_REDIS_STREAM: shadow:decision-events", f"      SHADOW_REDIS_STREAM: shadow:multi-replica-{project}"),
):
    if old not in text:
        raise SystemExit(f"Expected Compose setting not found: {old}")
    text = text.replace(old, new, 1)
replica = f'''  go-policy-replica:
    build:
      context: ./shadow-core-go
    environment:
      SHADOW_GO_ADDR: ":8081"
      SHADOW_GO_INTERNAL_TOKEN: ${{SHADOW_GO_INTERNAL_TOKEN:?set SHADOW_GO_INTERNAL_TOKEN in .env}}
      SHADOW_POSTGRES_DSN: postgres://shadow_core:${{SHADOW_POSTGRES_PASSWORD}}@postgres:5432/shadow_core?sslmode=disable
      SHADOW_REDIS_URL: redis://redis:6379/0
      SHADOW_REDIS_STREAM: shadow:multi-replica-{project}
    ports:
      - "127.0.0.1:{go_two_port}:8081"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/shadow-core-go", "--healthcheck"]
      interval: 10s
      timeout: 3s
      retries: 5

'''
marker = "\n  python-api:\n"
if text.count(marker) != 1:
    raise SystemExit("Could not locate unique insertion point for second Go service")
text = text.replace(marker, replica + marker, 1)
target.write_text(text)
PY

"${compose_bin[@]}" -p "$project" -f "$compose_test_file" config >/dev/null
# Enable cleanup before starting: Compose may create some resources and then fail.
started=1
"${compose_bin[@]}" -p "$project" -f "$compose_test_file" up -d --build postgres redis go-policy go-policy-replica >/dev/null

wait_health() {
  local port="$1" label="$2"
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "$label did not become healthy in the disposable project." >&2
  "${compose_bin[@]}" -p "$project" -f "$compose_test_file" ps >&2 || true
  "${compose_bin[@]}" -p "$project" -f "$compose_test_file" logs --tail=60 postgres redis go-policy go-policy-replica >&2 || true
  return 1
}
wait_health "$go_one_port" "First Go service"
wait_health "$go_two_port" "Second Go service"

# Use the exact token already bound into this disposable service, without echoing it.
first_container="$("${compose_bin[@]}" -p "$project" -f "$compose_test_file" ps -q go-policy)"
SHADOW_GO_INTERNAL_TOKEN="$(sudo docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$first_container" | awk -F= '$1 == "SHADOW_GO_INTERNAL_TOKEN" {print substr($0, index($0, "=") + 1); exit}')"
[[ "${#SHADOW_GO_INTERNAL_TOKEN}" -ge 32 ]] || { echo "Could not resolve the test service's internal token." >&2; exit 1; }
export SHADOW_GO_INTERNAL_TOKEN
request_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
payload_file="$tmpdir/request.json"
python3 - "$request_id" "$payload_file" <<'PY'
import json, sys
request_id, path = sys.argv[1:]
payload = {
    "request_id": request_id,
    "subject": "disposable-multireplica-test",
    "schema_version": "shadow.risk.v1",
    "signals": {
        "frida_detected": False,
        "root_integrity_failed": False,
        "jwt_validation_failures": 0,
        "grpc_tls_verified": True,
        "fft_beaconing_detected": False,
    },
    "correlation": {"source": "disposable-multireplica-test"},
}
with open(path, "w") as f:
    json.dump(payload, f, separators=(",", ":"))
PY

# Release the same idempotency key through both independent Go processes at once.
python3 - "$go_one_port" "$go_two_port" "$payload_file" "$tmpdir/results.json" <<'PY'
import concurrent.futures, json, sys, threading, urllib.error, urllib.request
ports = [int(sys.argv[1]), int(sys.argv[2])]
body = open(sys.argv[3], "rb").read()
results_path = sys.argv[4]
token = __import__("os").environ["SHADOW_GO_INTERNAL_TOKEN"]
workers = 32
barrier = threading.Barrier(workers)
def send(i):
    port = ports[i % 2]
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/decision", data=body,
        headers={"Content-Type": "application/json", "X-Shadow-Internal-Token": token},
        method="POST")
    try:
        barrier.wait(timeout=10)
        with urllib.request.urlopen(req, timeout=20) as response:
            return {"port": port, "status": response.status, "body": response.read().decode()}
    except urllib.error.HTTPError as exc:
        return {"port": port, "status": exc.code, "body": exc.read().decode()}
    except Exception as exc:
        return {"port": port, "status": 0, "error": type(exc).__name__}
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
    results = list(pool.map(send, range(workers)))
with open(results_path, "w") as f:
    json.dump(results, f)
counts = {}
for result in results:
    counts[result["status"]] = counts.get(result["status"], 0) + 1
print("Concurrent responses:", counts)
failures = [r for r in results if r["status"] != 200]
if failures:
    print("First failure:", {k:v for k,v in failures[0].items() if k != "body"}, failures[0].get("body", "")[:180])
    raise SystemExit(1)
decisions = [json.loads(r["body"]) for r in results]
if any(decision != decisions[0] for decision in decisions[1:]):
    raise SystemExit("Concurrent replicas returned different decisions for the same key")
PY

# A different body for the committed key must be rejected, not overwrite the decision.
conflict_status="$(python3 - "$go_two_port" "$payload_file" <<'PY'
import json, sys, urllib.error, urllib.request, os
port, path = int(sys.argv[1]), sys.argv[2]
payload = json.load(open(path))
payload["subject"] = "changed-subject-must-conflict"
request = urllib.request.Request(
    f"http://127.0.0.1:{port}/v1/decision",
    data=json.dumps(payload, separators=(",", ":")).encode(),
    headers={"Content-Type": "application/json", "X-Shadow-Internal-Token": os.environ["SHADOW_GO_INTERNAL_TOKEN"]},
    method="POST")
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        print(response.status)
except urllib.error.HTTPError as exc:
    print(exc.code)
PY
)"
[[ "$conflict_status" == 409 ]] || { echo "Changed payload for the same key returned HTTP $conflict_status, expected 409." >&2; exit 1; }

pg() {
  "${compose_bin[@]}" -p "$project" -f "$compose_test_file" exec -T postgres psql -U shadow_core -d shadow_core -Atq -c "$1" | tr -d '\r'
}
decision_count="$(pg "SELECT count(*) FROM risk_decisions WHERE request_id='${request_id}'::uuid")"
outbox_count="$(pg "SELECT count(*) FROM decision_outbox WHERE request_id='${request_id}'::uuid")"
[[ "$decision_count" == 1 && "$outbox_count" == 1 ]] || {
  echo "Expected one decision and outbox row; got decisions=$decision_count outbox=$outbox_count." >&2
  exit 1
}
stream="shadow:multi-replica-${project}"
stream_json="$("${compose_bin[@]}" -p "$project" -f "$compose_test_file" exec -T redis redis-cli --json XRANGE "$stream" - +)"
read -r deliveries event_ids < <(printf '%s\n' "$stream_json" | python3 -c '
import json, sys
request_id = sys.argv[1]
entries = json.load(sys.stdin)
matched = [dict(zip(e[1][::2], e[1][1::2])) for e in entries]
matched = [e for e in matched if e.get("request_id") == request_id]
print(len(matched), len({e.get("event_id") for e in matched}))
' "$request_id")
[[ "${deliveries:-0}" -ge 1 && "${event_ids:-0}" == 1 ]] || {
  echo "Expected at least one delivery with one stable event_id; got deliveries=${deliveries:-0}, distinct_event_ids=${event_ids:-0}." >&2
  exit 1
}
# Run a separate, rate-limited workload with unique synthetic request IDs.
# This is a short local smoke-load measurement, not a capacity benchmark.
load_run_id="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
load_results="$tmpdir/load-results.json"
load_request_ids="$tmpdir/load-request-ids.txt"
python3 scripts/run_bounded_load.py "$go_one_port" "$go_two_port" "$load_run_id" "$load_results" "$load_request_ids"
load_request_count="$(wc -l < "$load_request_ids" | tr -d ' ')"
load_decisions="$(pg "SELECT count(*) FROM risk_decisions WHERE subject LIKE '${load_run_id}-%'")"
load_outbox="$(pg "SELECT count(*) FROM decision_outbox o JOIN risk_decisions d USING (request_id) WHERE d.subject LIKE '${load_run_id}-%'")"
[[ "$load_decisions" == "$load_request_count" && "$load_outbox" == "$load_request_count" ]] || {
  echo "Expected $load_request_count load decisions/outbox rows; got decisions=$load_decisions outbox=$load_outbox." >&2
  exit 1
}

# The publisher is asynchronous; allow a bounded 20-second delivery window.
load_stream_json='[]'
load_delivered=0
load_covered=0
load_stable=0
load_duplicate_deliveries=0
for _ in $(seq 1 40); do
  load_stream_json="$("${compose_bin[@]}" -p "$project" -f "$compose_test_file" exec -T redis redis-cli --json XRANGE "$stream" - +)"
  read -r load_delivered load_covered load_stable load_duplicate_deliveries < <(python3 -c '
import json, sys
wanted = set(open(sys.argv[1], encoding="utf-8").read().split())
entries = json.load(sys.stdin)
by_request = {}
for entry in entries:
    values = dict(zip(entry[1][::2], entry[1][1::2]))
    request_id = values.get("request_id")
    if request_id in wanted:
        by_request.setdefault(request_id, set()).add(values.get("event_id"))
covered = sum(1 for request_id in wanted if request_id in by_request)
stable = all(len(ids) == 1 and None not in ids for ids in by_request.values())
delivered = sum(1 for entry in entries if dict(zip(entry[1][::2], entry[1][1::2])).get("request_id") in wanted)
print(delivered, covered, int(stable), max(0, delivered - covered))
' "$load_request_ids" <<<"$load_stream_json")
  if [[ "$load_covered" == "$load_request_count" && "$load_stable" == 1 ]]; then break; fi
  sleep 0.5
done
[[ "$load_covered" == "$load_request_count" && "$load_stable" == 1 ]] || {
  echo "Redis load delivery incomplete: covered=$load_covered/$load_request_count stable_event_ids=$load_stable." >&2
  exit 1
}
printf 'Load persistence: %s decisions and %s outbox rows; Redis: %s/%s request IDs, %s entries (%s repeated deliveries).\n' \
  "$load_decisions" "$load_outbox" "$load_covered" "$load_request_count" "$load_delivered" "$load_duplicate_deliveries"

printf 'PASS: %s concurrent same-key requests across two Go processes; one PostgreSQL decision/outbox; changed payload returned 409; Redis deliveries=%s with one stable event_id.\n' "$project" "$deliveries"
printf 'Ports were loopback-only: PostgreSQL=%s Redis=%s Go=%s/%s. Cleanup removes only this isolated project and its fresh volumes.\n' "$pg_port" "$redis_port" "$go_one_port" "$go_two_port"
