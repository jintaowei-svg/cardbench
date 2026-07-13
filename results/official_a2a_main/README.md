# Official A2A main results (completed six-model snapshot)

This directory contains the completed Official A2A main experiment outputs synced from `/home/wjt/CardDiffBench_official_a2a_main_20260712/results/official_a2a_main`.

Included models:

- `gpt-5-mini`: rows=3150, success=3116, ASR=98.92%, non_judgment=0, B2=0, duplicates=0
- `gpt-5.6-Luna`: rows=3150, success=3054, ASR=96.95%, non_judgment=0, B2=0, duplicates=0
- `gpt-5.4-mini`: rows=3150, success=2900, ASR=92.06%, non_judgment=0, B2=0, duplicates=0
- `gemini-2.5-flash`: rows=3150, success=3135, ASR=99.52%, non_judgment=0, B2=0, duplicates=0
- `gemini-3.5-flash`: rows=3150, success=3007, ASR=95.46%, non_judgment=0, B2=0, duplicates=0
- `claude-sonnet-5`: rows=3150, success=2858, ASR=90.73%, non_judgment=0, B2=0, duplicates=0

Notes:

- `deepseek-v4-flash` and `grok-4.5` were still running when this snapshot was prepared, so they are intentionally excluded from this completed-results commit.
- Full per-trial records are in each model directory as `details.jsonl`.
- File checksums are recorded in `official_a2a_completed6_file_sha256.json`.
- Aggregate integrity/statistics are recorded in `official_a2a_completed6_summary.json`.
