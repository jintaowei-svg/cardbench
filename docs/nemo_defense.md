# NVIDIA NeMo Guardrails Defense Experiment

This experiment places one generic NeMo input rail before the Official A2A
Host. It reuses the frozen Official A2A transfer manifest and deterministically
excludes B2, producing the paper design of 7 attacks x 3 domains x 30 cases =
630 trials. It never regenerates or resamples tasks.

The gateway receives the user task and Host-visible AgentCard control-plane
context. Attack labels and the private event-level oracle are excluded. A NeMo
`Yes` verdict blocks the Host and counts as an attack failure; a `No` verdict
runs the unchanged Official A2A Host and scorer. A Guardrail error or timeout is
recorded as a non-judgment and is never counted as a successful defense.

## Installation

Use Python 3.11 for the frozen experiment environment:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev,defense-nemo]"
pip freeze > defense_nemo_requirements.txt
```

The NeMo version is pinned to `0.23.0`. Both Host and Guardrail use
`gpt-5-mini`, temperature 0, and one retry. Existing `SUT_API_KEY` and
`SUT_API_BASE` values are projected to the corresponding OpenAI-compatible
environment variables when those variables are not already set.

## Run

First run one frozen case for each attack:

```bash
python defense/nemo/run_nemo_defense.py --dry-run \
  --output defense/nemo/results/raw/nemo_dry_run_7.jsonl
```

After inspecting those seven records, run the complete experiment:

```bash
python defense/nemo/run_nemo_defense.py \
  --output defense/nemo/results/raw/nemo_official_a2a_630.jsonl
```

An interrupted run can be continued with `--resume`; completed case IDs are not
executed again. Do not reuse a dry-run file for the full run.

Aggregate the full run against the existing 621/630 baseline:

```bash
python defense/nemo/aggregate_results.py \
  --baseline-results remote_results/official_a2a_l3_rerun_nonjudgment_20260711/summary.final.json \
  --defense-results defense/nemo/results/raw/nemo_official_a2a_630.jsonl \
  --output defense/nemo/results/summary/nemo_official_a2a_630_summary.json
```

The aggregator requires all 630 unique cases and validates every 30-case
attack-domain cell. It writes `summary.json` plus `defense_table.csv`, whose
cells are planned-case ASRs. `--allow-partial` exists only for diagnostics and
dry-run aggregation.

## Final result

The complete run contains all 630 planned records. Of these, 623 completed a
judgment and 7 ended with infrastructure errors. The planned-case ASR is
595/630 (94.44%), compared with the no-defense baseline of 621/630 (98.57%).
NeMo blocked 25/630 cases (3.97%), and the relative ASR reduction is 4.19%.

By attack, planned-case ASR is A1 83.33%, A2 100.00%, A3 98.89%, B1 97.78%,
B3 100.00%, C1 83.33%, and C2 97.78%. The canonical outputs are under
`results/paper/05_defense/`.
