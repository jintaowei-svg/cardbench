#!/usr/bin/env bash
set -euo pipefail

cd /home/wjt/CardDiffBench_official_a2a_main_20260712
if [[ "$(id -un)" != "wjt" ]]; then
  echo "Refusing to run outside the wjt account." >&2
  exit 1
fi

set -a
. ./.env
set +a

mkdir -p logs/formal results/official_a2a_main
models=(gpt-5-mini gpt-5.6-Luna gpt-5.4-mini gemini-2.5-flash)

for model in "${models[@]}"; do
  pidfile="logs/formal/${model}.pid"
  if [[ -f "$pidfile" ]]; then
    old_pid="$(cat "$pidfile")"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      owner="$(ps -o user= -p "$old_pid" | xargs)"
      if [[ "$owner" == "wjt" ]]; then
        echo "$model already running as wjt PID $old_pid"
        continue
      fi
      echo "Refusing to interact with non-wjt PID $old_pid" >&2
      exit 1
    fi
  fi
  nohup .venv/bin/python scripts/run_official_a2a_main.py run \
    --model "$model" \
    --manifest attacks/carddiff/official_a2a_main_3150.json \
    --results-root results/official_a2a_main \
    > "logs/formal/${model}.log" 2>&1 &
  pid="$!"
  echo "$pid" > "$pidfile"
  echo "$model $pid"
done
