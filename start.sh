#!/usr/bin/env bash
# Launch the whole ctf-brain stack: aggregator + tmux collector, then open the UI.
# Ctrl-C tears everything down.
set -euo pipefail

cd "$(dirname "$0")"

# Load .env if present (for ANTHROPIC_API_KEY and CTF_* overrides).
if [[ -f .env ]]; then
  set -a; . ./.env; set +a
fi

PY="${PYTHON:-python3}"
HOST="${CTF_HOST:-127.0.0.1}"
PORT="${CTF_PORT:-7331}"
URL="http://${HOST}:${PORT}"

if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  echo "⚠️  ANTHROPIC_API_KEY not set — collectors/UI will run but chat is disabled."
  echo "    Set it in .env (see .env.example) and re-run to enable chat."
fi

pids=()
cleanup() {
  echo
  echo "Shutting down…"
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "Starting aggregator on ${URL} …"
"$PY" -m aggregator.main &
pids+=($!)

# Wait for the aggregator to answer /health (up to ~10s).
for _ in $(seq 1 50); do
  if curl -sf "${URL}/health" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
if ! curl -sf "${URL}/health" >/dev/null 2>&1; then
  echo "❌ aggregator did not come up — check the logs above."
  exit 1
fi
echo "✅ aggregator up."

echo "Starting tmux collector …"
"$PY" -m aggregator.tmux_poll &
pids+=($!)

echo "Opening UI: ${URL}"
( xdg-open "${URL}" >/dev/null 2>&1 || open "${URL}" >/dev/null 2>&1 || true ) &

echo
echo "Running. Load the browser extension from ./extension (chrome://extensions →"
echo "Developer mode → Load unpacked). Optional app logs:"
echo "  $PY -m aggregator.tail burp --file /tmp/burp_http.log"
echo
echo "Press Ctrl-C to stop everything."
wait
