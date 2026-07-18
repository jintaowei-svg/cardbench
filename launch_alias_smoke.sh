#!/usr/bin/env bash
set -euo pipefail
cd /home/wjt/CardDiffBench_official_a2a_main_20260712
sed -i 's/^CARDDIFF_CODE_SHA=.*/CARDDIFF_CODE_SHA=5c5b541e3d64d6be7a496abb024e88e6a726aef6/' .env
set -a
. ./.env
set +a
mkdir -p logs/smoke_alias
for model in gpt-5.6-Luna claude-haiku-4.5; do
  nohup .venv/bin/python scripts/run_official_a2a_main.py run --model "$model" --smoke 21 --results-root results/official_a2a_smoke_alias > "logs/smoke_alias/$model.log" 2>&1 &
  echo "$model $!"
done
