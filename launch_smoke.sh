#!/usr/bin/env bash
set -euo pipefail
cd /home/wjt/CardDiffBench_official_a2a_main_20260712
set -a
. ./.env
set +a
mkdir -p logs/smoke
for model in gpt-5-mini gpt-5.6-Luna gpt-5.4-mini gemini-2.5-flash gemini-3.5-flash claude-haiku-4.5; do
  nohup .venv/bin/python scripts/run_official_a2a_main.py run --model "$model" --smoke 21 > "logs/smoke/$model.log" 2>&1 &
  echo "$model $!"
done
