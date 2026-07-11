# Official A2A LLM downstream partial run

This directory contains the paused pilot run for the LLM-backed downstream impact experiment.

- Config: `configs/downstream/official_a2a_llm_downstream.yaml`
- Model: `gpt-5-mini`
- Status: paused before completion
- Completed cases: 153 / 621
- Observed impacts: 51
- Partial DIR with fixed 621-case denominator: 0.0821256038647343

The manifest is ordered by attack type. This partial run covers all A1 cases and part of A2 only:

- A1: 85 completed, 3 impacts
- A2: 68 completed, 48 impacts
- A3/B1/B3/C1/C2: not reached in this partial run

`details.jsonl` is the row-level evidence file. `summary.json` was generated from the partial `details.jsonl` with `scripts/summarize_downstream_impact.py`.
