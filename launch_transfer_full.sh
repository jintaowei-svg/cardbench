#!/usr/bin/env bash
set -euo pipefail

root=/home/wjt/CardDiffBench_transfer_full_20260716
cd "$root"
[[ "$(id -un)" == "wjt" ]] || {
  echo "Refusing to run outside the wjt account." >&2
  exit 1
}

set -a
. ./.env
set +a

export CARDDIFF_AGNTCY_DIRCTL_PATH="$root/.runtime/agntcy/dirctl-linux-amd64"
export CARDDIFF_AGNTCY_DIRECTORY_ADDRESS=127.0.0.1:8888

mkdir -p logs/transfer_full results/transfer_full

ensure_agntcy_directory() {
  if (echo > /dev/tcp/127.0.0.1/8888) >/dev/null 2>&1; then
    return
  fi
  local pidfile=logs/transfer_full/agntcy-daemon.pid
  if [[ -f "$pidfile" ]]; then
    local old_pid owner cmd
    old_pid="$(cat "$pidfile")"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      owner="$(ps -o user= -p "$old_pid" | xargs)"
      cmd="$(tr '\0' ' ' < "/proc/$old_pid/cmdline")"
      [[ "$owner" == "wjt" && "$cmd" == *"dirctl-linux-amd64 daemon start"* ]] || {
        echo "Refusing to interact with unrelated PID $old_pid." >&2
        exit 1
      }
    fi
  fi
  mkdir -p .runtime/agntcy/data
  nohup "$CARDDIFF_AGNTCY_DIRCTL_PATH" daemon start \
    --data-dir .runtime/agntcy/data \
    >> logs/transfer_full/agntcy-daemon.log 2>&1 &
  echo "$!" > "$pidfile"
  for _ in {1..30}; do
    (echo > /dev/tcp/127.0.0.1/8888) >/dev/null 2>&1 && return
    sleep 1
  done
  echo "AGNTCY directory did not become ready." >&2
  exit 1
}

ensure_agntcy_directory

for target in anp nlip agntcy autogen langgraph; do
  case "$target" in
    anp|nlip)
      python="$root/.venv-native/bin/python"
      module=harness.transfer_native.runner
      ;;
    agntcy)
      python="$root/.venv-agntcy/bin/python"
      module=harness.transfer_native.runner
      ;;
    autogen|langgraph)
      python="$root/.venv-framework/bin/python"
      module=harness.transfer_framework.runner
      ;;
  esac

  output="results/transfer_full/$target/supplement.jsonl"
  log="logs/transfer_full/$target.log"
  pidfile="logs/transfer_full/$target.pid"
  if [[ -f "$pidfile" ]]; then
    old_pid="$(cat "$pidfile")"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      owner="$(ps -o user= -p "$old_pid" | xargs)"
      cmd="$(tr '\0' ' ' < "/proc/$old_pid/cmdline")"
      [[ "$owner" == "wjt" && "$cmd" == *"$module"* && "$cmd" == *"configs/transfer_full/$target.yaml"* && "$cmd" == *"$output"* ]] || {
        echo "Refusing to interact with unrelated PID $old_pid." >&2
        exit 1
      }
      echo "$target already running as wjt PID $old_pid"
      continue
    fi
  fi

  mkdir -p "$(dirname "$output")"
  printf '\n[%s] starting %s full supplement\n' "$(date -Is)" "$target" >> "$log"
  nohup "$python" -m "$module" "configs/transfer_full/$target.yaml" \
    --output "$output" \
    --case-id-manifest attacks/carddiff/transfer_full/run_case_ids.json \
    --resume >> "$log" 2>&1 &
  pid="$!"
  echo "$pid" > "$pidfile"
  echo "$target $pid"
done
