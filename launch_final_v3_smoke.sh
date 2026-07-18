#!/usr/bin/env bash
set -euo pipefail
cd /home/wjt/CardDiffBench_official_a2a_main_20260712
sed -i 's/^CARDDIFF_CODE_SHA=.*/CARDDIFF_CODE_SHA=736833100bcda47c3efc9bcf06d0a61172872176/' .env
set -a
. ./.env
set +a
mkdir -p logs/smoke_final_v3
for model in gpt-5-mini gpt-5.6-Luna gpt-5.4-mini gemini-2.5-flash gemini-3.5-flash claude-haiku-4.5; do
  nohup .venv/bin/python scripts/run_official_a2a_main.py run --model "$model" --smoke 7 --results-root results/official_a2a_smoke_final_v3 > "logs/smoke_final_v3/$model.log" 2>&1 &
  echo "$model $!"
done
