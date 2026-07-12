# Official A2A LLM downstream pilot v1

This directory contains the paused pilot run for the LLM-backed downstream impact experiment.

- Original implementation: commit `6a25615`
- Model: `gpt-5-mini`
- Status: paused debugging pilot; not compatible with v2 results
- Completed cases: 153 / 621
- Observed impacts: 51
- Partial DIR over completed cases: 51 / 153 = 0.3333333333333333

The manifest is ordered by attack type. This partial run covers all A1 cases and part of A2 only:

- A1: 85 completed, 3 impacts
- A2: 68 completed, 48 impacts
- A3/B1/B3/C1/C2: not reached in this partial run

`details.jsonl` is the row-level debugging evidence file. `summary.json` was
regenerated with `scripts/summarize_downstream_impact.py` so that a partial run
uses the completed-case denominator. Unrun cases are not counted as failures.

The v2 experiment writes to `results/downstream/official_a2a_llm_rqd1_v2/`
and must start from the first manifest case. These pilot rows must not be
appended to or merged with v2 results.
