#!/usr/bin/env bash
# Start the image the way an upgraded installation would and check what unit tests can't see:
#   - the server ends up running unprivileged, on a data volume an older (root) image wrote;
#   - it can still use a TLS key that is root-only and mounted read-only;
#   - `docker stop` with chargers connected is a prompt, clean exit, and what they did is saved.
#
#   scripts/container-smoke-test.sh [image] [extra `docker run` arguments...]
#
# Everything is probed from inside the container, so no ports are published.
set -euo pipefail

IMAGE="${1:-grizzle-local:ci}"
shift || true
NAME="grizzle-smoke-$$"
VOLUME="grizzle-smoke-data-$$"
CERTS="$(mktemp -d)"
HERE="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
    rm -rf "$CERTS"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    docker logs "$NAME" 2>&1 | tail -40 >&2 || true
    exit 1
}
py() { docker exec "$NAME" python -c "$1"; }
health() { py "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:9000/health', timeout=3))['$1'])"; }
wait_until() { # wait_until <description> <command...>
    local what="$1"
    shift
    for _ in $(seq 1 60); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 0.5
    done
    fail "timed out waiting for: $what"
}

echo "== volumes as an older image left them: root-owned state, a root-only key mounted read-only"
"$HERE/make-cert.sh" "$CERTS" >/dev/null 2>&1
docker volume create "$VOLUME" >/dev/null
docker run --rm --entrypoint sh -v "$VOLUME:/data" "$IMAGE" -c \
    'echo "{}" > /data/state.json && chown 0:0 /data /data/state.json && chmod 644 /data/state.json'

docker run -d --name "$NAME" -e GRIZZLE_API_PASSWORD="smoke test password" \
    -v "$VOLUME:/data" -v "$CERTS:/certs:ro" "$@" "$IMAGE" >/dev/null
wait_until "the server to answer /health" health status

echo "== the server is unprivileged"
status="$(docker exec "$NAME" cat /proc/1/status)"
uid="$(awk '/^Uid:/{print $2}' <<<"$status")"
caps="$(awk '/^CapEff:/{print $2}' <<<"$status")"
nnp="$(awk '/^NoNewPrivs:/{print $2}' <<<"$status")"
[ "$uid" = "10001" ] || fail "the server runs as uid $uid, expected 10001"
[ "$caps" = "0000000000000000" ] || fail "the server kept capabilities: $caps"
[ "$nnp" = "1" ] || fail "no_new_privs is not set"
owner="$(docker exec "$NAME" stat -c '%u %a' /data/state.json)"
[ "$owner" = "10001 600" ] || fail "state.json is '$owner', expected '10001 600'"

echo "== TLS works from a key the unprivileged user could not read"
docker logs "$NAME" 2>&1 | grep -q "and wss:// on 8443" || fail "the TLS listener did not start"
py "import ssl,urllib.request; urllib.request.urlopen('https://127.0.0.1:8443/health', context=ssl._create_unverified_context(), timeout=4)" ||
    fail "no answer on the TLS port"

echo "== chargers connect (plain and TLS)"
docker exec -d "$NAME" python tools/fake_charger.py ws://127.0.0.1:9000/ocpp1.6/GRD-SMOKE001
docker exec -d "$NAME" python tools/fake_charger.py wss://127.0.0.1:8443/ocpp1.6/GRD-SMOKE002 --insecure
online() { [ "$(health stationsOnline)" = "2" ]; }
wait_until "both chargers to be online" online

echo "== docker stop is a prompt, clean exit"
started="$(date +%s)"
docker stop -t 10 "$NAME" >/dev/null
took="$(($(date +%s) - started))"
code="$(docker inspect -f '{{.State.ExitCode}}' "$NAME")"
[ "$code" = "0" ] || fail "exit code $code after docker stop (137 means it had to be killed)"
[ "$took" -lt 8 ] || fail "docker stop took ${took}s"

echo "== and what happened was saved"
docker run --rm --entrypoint python -v "$VOLUME:/data" "$IMAGE" -c "
import json
stations = json.load(open('/data/state.json'))['stations']
assert {'GRD-SMOKE001', 'GRD-SMOKE002'} <= set(stations), sorted(stations)
assert stations['GRD-SMOKE001']['boot']['chargePointModel'] == 'GRD 40A 2025'
" || fail "the stations were not in the saved state"

echo "== it starts again on its own volume"
docker start "$NAME" >/dev/null
wait_until "the restarted server to answer /health" health status
[ "$(health stationCount)" = "2" ] || fail "the restarted server does not know its stations"

echo "OK: $IMAGE passed the container smoke test"
