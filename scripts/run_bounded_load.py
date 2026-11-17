#!/usr/bin/env python3
"""Short, rate-limited synthetic load for the disposable local Go stack."""
import concurrent.futures
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
import uuid

if len(sys.argv) != 6:
    raise SystemExit("usage: run_bounded_load.py GO1_PORT GO2_PORT RUN_ID RESULTS_JSON REQUEST_IDS")
ports = [int(sys.argv[1]), int(sys.argv[2])]
run_id, results_path, request_ids_path = sys.argv[3:]
token = os.environ["SHADOW_GO_INTERNAL_TOKEN"]
request_count = 150
rate_per_second = 5.0
max_workers = 12
request_ids = [str(uuid.uuid4()) for _ in range(request_count)]

def send(index):
    request_id = request_ids[index]
    payload = {
        "request_id": request_id,
        "subject": f"{run_id}-{index:03d}",
        "schema_version": "shadow.risk.v1",
        "signals": {
            "frida_detected": False,
            "root_integrity_failed": False,
            "jwt_validation_failures": 0,
            "grpc_tls_verified": True,
            "fft_beaconing_detected": False,
        },
        "correlation": {"source": "bounded-synthetic-load", "sequence": index},
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    port = ports[index % len(ports)]
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/decision",
        data=body,
        headers={"Content-Type": "application/json", "X-Shadow-Internal-Token": token},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response_body = response.read()
            status = response.status
        parsed = json.loads(response_body)
        valid_json = isinstance(parsed, dict)
        error = None
    except urllib.error.HTTPError as exc:
        status = exc.code
        valid_json = False
        error = exc.read().decode("utf-8", "replace")[:240]
    except Exception as exc:
        status = 0
        valid_json = False
        error = type(exc).__name__
    return {
        "request_id": request_id,
        "port": port,
        "status": status,
        "valid_json": valid_json,
        "latency_ms": (time.perf_counter() - started) * 1000,
        "error": error,
    }

start = time.perf_counter()
futures = []
with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
    for index in range(request_count):
        scheduled = start + index / rate_per_second
        delay = scheduled - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        futures.append(pool.submit(send, index))
    results = [future.result() for future in futures]
elapsed = time.perf_counter() - start
with open(results_path, "w", encoding="utf-8") as output:
    json.dump(results, output)
with open(request_ids_path, "w", encoding="utf-8") as output:
    output.write("\n".join(request_ids) + "\n")

statuses = {}
for result in results:
    statuses[str(result["status"])] = statuses.get(str(result["status"]), 0) + 1
latencies = sorted(result["latency_ms"] for result in results)
p95 = latencies[max(0, int(0.95 * len(latencies)) - 1)]
successes = [r for r in results if r["status"] == 200 and r["valid_json"]]
print(
    f"Synthetic load: {request_count} unique requests, {rate_per_second:g} requests/s "
    f"scheduled over {request_count / rate_per_second:.0f}s; max concurrency {max_workers}; "
    f"two Go processes (round-robin)."
)
print(
    f"Responses: {len(successes)}/{request_count} HTTP 200 with JSON; statuses={statuses}; "
    f"wall={elapsed:.2f}s; achieved={request_count / elapsed:.2f} req/s; "
    f"latency ms p50={statistics.median(latencies):.1f}, p95={p95:.1f}, "
    f"max={max(latencies):.1f}."
)
failures = [r for r in results if r["status"] != 200 or not r["valid_json"]]
if failures:
    print("First failure:", {k: v for k, v in failures[0].items() if k != "request_id"})
    raise SystemExit(1)
