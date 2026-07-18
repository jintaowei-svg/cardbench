#!/usr/bin/env bash
set -euo pipefail
cd /home/wjt/CardDiffBench_official_a2a_main_20260712
sed -i 's/^CARDDIFF_CODE_SHA=.*/CARDDIFF_CODE_SHA=0c81c52bbf0129e3b174e8324337db83ebff9194/' .env
set -a
. ./.env
set +a
mkdir -p logs/smoke_json_mode
for model in gpt-5-mini gpt-5.6-Luna gpt-5.4-mini gemini-2.5-flash gemini-3.5-flash claude-haiku-4.5; do
  nohup .venv/bin/python scripts/run_official_a2a_main.py run --model "$model" --smoke 21 --results-root results/official_a2a_smoke_json_mode > "logs/smoke_json_mode/$model.log" 2>&1 &
  echo "$model $!"
done
