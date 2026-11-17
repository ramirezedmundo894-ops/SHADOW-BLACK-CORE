#!/usr/bin/env bash
# Runs PostgreSQL and Redis consumer integration tests with disposable services.
# It never connects to the project's normal Compose services or local SQLite.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
compose_bin=(sudo docker)
suffix="$(date +%s)-$$"
container="shadow-event-inbox-test-$suffix"
redis_container="shadow-event-redis-test-$suffix"

if [[ -f "$root/data/shadow-core.sqlite3" ]]; then
  sqlite_state="present:$(stat -c '%s' "$root/data/shadow-core.sqlite3"):$(sha256sum "$root/data/shadow-core.sqlite3" | awk '{print $1}')"
else
  sqlite_state=absent
fi

read -r pg_port redis_port <<<"$(python3 - <<'PY'
import socket
ports = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sock.close()
print(*ports)
PY
)"
password="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
cleanup() {
  local result=$?
  "${compose_bin[@]}" rm -f -v "$container" "$redis_container" >/dev/null 2>&1 || true
  if [[ -f "$root/data/shadow-core.sqlite3" ]]; then
    local current="present:$(stat -c '%s' "$root/data/shadow-core.sqlite3"):$(sha256sum "$root/data/shadow-core.sqlite3" | awk '{print $1}')"
  else
    local current=absent
  fi
  if [[ "$current" != "$sqlite_state" ]]; then
    echo "Local SQLite fingerprint changed during the isolated test." >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT

"${compose_bin[@]}" run --detach --rm --name "$container" \
  --env POSTGRES_DB=shadow_core_test \
  --env POSTGRES_USER=shadow_test \
  --env "POSTGRES_PASSWORD=$password" \
  --publish "127.0.0.1:${pg_port}:5432" \
  postgres:16-alpine >/dev/null
"${compose_bin[@]}" run --detach --rm --name "$redis_container" \
  --publish "127.0.0.1:${redis_port}:6379" \
  redis:7-alpine redis-server --save "" --appendonly no >/dev/null

pg_ready=0
redis_ready=0
for _ in $(seq 1 60); do
  if [[ "$pg_ready" != 1 ]] && "${compose_bin[@]}" exec "$container" pg_isready -U shadow_test -d shadow_core_test >/dev/null 2>&1; then
    pg_ready=1
  fi
  if [[ "$redis_ready" != 1 ]] && "${compose_bin[@]}" exec "$redis_container" redis-cli ping 2>/dev/null | grep -q PONG; then
    redis_ready=1
  fi
  if [[ "$pg_ready" == 1 && "$redis_ready" == 1 ]]; then
    break
  fi
  sleep 1
done
if [[ "$pg_ready" != 1 || "$redis_ready" != 1 ]]; then
  echo "Disposable PostgreSQL or Redis did not become ready." >&2
  "${compose_bin[@]}" logs "$container" "$redis_container" >&2 || true
  exit 1
fi

cd "$root/shadow-core-go"
SHADOW_TEST_POSTGRES_DSN="postgres://shadow_test:${password}@127.0.0.1:${pg_port}/shadow_core_test?sslmode=disable" \
SHADOW_TEST_REDIS_URL="redis://127.0.0.1:${redis_port}/0" \
  go test ./... -count=1
