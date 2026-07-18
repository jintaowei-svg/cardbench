#!/usr/bin/env bash
set -euo pipefail

root=/home/wjt/CardDiffBench_official_a2a_main_20260712
cd "$root"
[[ "$(id -un)" == "wjt" ]] || { echo "Not wjt; refusing." >&2; exit 1; }

pids=(3406831 3406832 3406833 3406834 3406835 3423878 3423879 3423880 3423881)
for pid in "${pids[@]}"; do
  [[ -r "/proc/$pid/cmdline" ]] || continue
  owner="$(ps -o user= -p "$pid" | xargs)"
  cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline")"
  if [[ "$owner" != "wjt" ]]; then
    echo "Refusing non-wjt PID $pid" >&2
    exit 1
  fi
  if [[ "$cmd" != *"scripts/run_official_a2a_main.py run"* ]] ||
     [[ "$cmd" != *"--results-root results/official_a2a_main"* ]]; then
    echo "Refusing unrelated wjt PID $pid: $cmd" >&2
    exit 1
  fi
  kill -TERM "$pid"
  echo "terminated duplicate/formal PID $pid"
done

for _ in {1..20}; do
  alive=0
  for pid in "${pids[@]}"; do
    kill -0 "$pid" 2>/dev/null && alive=1
  done
  [[ "$alive" == 0 ]] && break
  sleep 0.25
done

for pid in "${pids[@]}"; do
  if kill -0 "$pid" 2>/dev/null; then
    owner="$(ps -o user= -p "$pid" | xargs)"
    [[ "$owner" == "wjt" ]] || { echo "Owner changed for PID $pid" >&2; exit 1; }
    kill -KILL "$pid"
  fi
done

archive="results/official_a2a_main_archive/duplicate_concurrent_start_20260712T2145"
mkdir -p "$archive/models" "$archive/logs"
for model in gpt-5-mini gpt-5.6-Luna gpt-5.4-mini gemini-2.5-flash gemini-3.5-flash; do
  if [[ -d "results/official_a2a_main/$model" ]]; then
    mv "results/official_a2a_main/$model" "$archive/models/$model"
  fi
done
if [[ -d logs/formal ]]; then
  mv logs/formal "$archive/logs/formal"
fi
printf '%s\n' \
  'Reason: two concurrent formal process sets wrote identical case IDs to the same model files.' \
  'Action: all affected wjt-owned processes stopped; raw partial outputs preserved here; clean four-model restart required.' \
  'Excluded model: gemini-3.5-flash was stopped and will not be restarted.' \
  > "$archive/README.txt"
echo "$archive"
