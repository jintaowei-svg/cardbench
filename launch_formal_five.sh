#!/usr/bin/env bash
set -euo pipefail
cd /home/wjt/CardDiffBench_official_a2a_main_20260712
set -a
. ./.env
set +a
mkdir -p logs/formal
models=(gpt-5-mini gpt-5.6-Luna gpt-5.4-mini gemini-2.5-flash gemini-3.5-flash)
for model in "${models[@]}"; do
  nohup .venv/bin/python scripts/run_official_a2a_main.py run \
    --model "$model" \
    --manifest attacks/carddiff/official_a2a_main_3150.json \
    --results-root results/official_a2a_main \
    > "logs/formal/$model.log" 2>&1 &
  echo "$model $!"
done
