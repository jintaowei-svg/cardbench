# Official A2A main results (completed eight-model matrix)

This directory contains the completed Official A2A main experiment outputs synced from `/home/wjt/CardDiffBench_official_a2a_main_20260712/results/official_a2a_main`.

The formal matrix contains 25,200 trials with 24,240 successful attacks
(ASR 96.19%). Included models:

- `gpt-5-mini`: rows=3150, success=3116, ASR=98.92%, non_judgment=0, B2=0, duplicates=0
- `gpt-5.6-Luna`: rows=3150, success=3054, ASR=96.95%, non_judgment=0, B2=0, duplicates=0
- `gpt-5.4-mini`: rows=3150, success=2900, ASR=92.06%, non_judgment=0, B2=0, duplicates=0
- `gemini-2.5-flash`: rows=3150, success=3135, ASR=99.52%, non_judgment=0, B2=0, duplicates=0
- `gemini-3.5-flash`: rows=3150, success=3007, ASR=95.46%, non_judgment=0, B2=0, duplicates=0
- `claude-sonnet-5`: rows=3150, success=2858, ASR=90.73%, non_judgment=0, B2=0, duplicates=0
- `deepseek-v4-flash`: rows=3150, success=3105, ASR=98.57%, parse_failures=3, B2=0, duplicates=0
- `grok-4.5`: rows=3150, success=3065, ASR=97.30%, non_judgment=0, B2=0, duplicates=0

Notes:

- Full per-trial records are in each model directory as `details.jsonl`.
- `claude-haiku-4.5/smoke` is a smoke run and is excluded from the formal matrix.
- `official_a2a_completed6_summary.json` and its checksum file are retained as
  historical six-model snapshot metadata; they are not the formal matrix source.
- The aligned eight-model summary is generated at
  `results/paper/02_cross_model/summary.json`.
