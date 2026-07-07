# CardDiffBench

CardDiffBench is a benchmark for evaluating AgentCard control-plane
differentials in agent-to-agent systems. It tests whether a Host makes unsafe
decisions when public AgentCards, authenticated extended AgentCards, interfaces,
tenant bindings, authorization scopes, and output modes disagree.

This branch is CardDiff-first. The original A2ASecBench codebase is preserved
only as reference material under `reference/archive/a2asecbench/`; active
experiments, prompts, cases, configs, SUTs, and tests live in the CardDiff paths
listed below.

## What CardDiffBench Measures

CardDiffBench focuses on Host control-plane behavior around AgentCard state:

| Family | Attack types | What can go wrong |
| --- | --- | --- |
| Extended-card differentials | A1, A2, A3 | A Host trusts authenticated extended-card state that diverges from the public card. |
| Interface and tenant confusion | B1, B2, B3 | A Host routes through the wrong ordered interface, tenant, binding, or protocol version. |
| Policy and output-mode drift | C1, C2 | A Host invokes restricted skills or accepts artifacts outside the requested output modes. |

CardDiffBench borrows the scenario-adapter generation style from A2ASecBench,
but the attack taxonomy, case schema, perturbation dataset, and scoring oracles
are CardDiffBench-specific.

## Repository Layout

```text
attacks/carddiff/       Frozen CardDiff cases, perturbations, schema, scenarios, and vectors
prompts/carddiff/       Scenario-adapter prompt templates
configs/                Offline and LLM-backed CardDiff run configs
harness/                Local CardDiff A2A HTTP environment and scoring
sut/carddiff/           Deterministic and LLM-backed CardDiff Host SUTs
scripts/                Case generation, validation, and smoke-run helpers
tests/                  CardDiff regression tests
paper_drafts/           Draft manuscript and prompt appendix notes
reference/archive/      Archived A2ASecBench reference snapshot
```

## Dataset

The active frozen dataset is built from:

- `attacks/carddiff/vectors.json`
- `attacks/carddiff/scenarios.json`
- `attacks/carddiff/scenario_tasks.json`
- `attacks/carddiff/perturbations.json`
- `attacks/carddiff/cases.jsonl`
- `attacks/carddiff/perturbed_cases.jsonl`

The current frozen split contains 72 base scenario-adapted cases and 720
perturbed cases.

## Installation

Python 3.10 or newer is required.

```bash
pip install -e ".[dev]"
```

## Run CardDiffBench

Run the deterministic Host SUT against the full perturbed dataset:

```bash
python orchestration.py --config configs/offline/carddiff_perturbed_all.yaml --trials 1
```

Each run writes:

- `results/run_<timestamp>.jsonl` with per-trial records
- `results/summary.json` with aggregate ASR and CardDiff breakdowns by attack
  type and scenario

## LLM-Backed Host Runs

LLM runs are opt-in. Set credentials in the environment or in `.env`:

```bash
SUT_API_BASE=...
SUT_API_KEY=...
SUT_MODEL=...
SUT_TRUST_ENV=false
```

Then run an LLM config:

```bash
python orchestration.py --config configs/llm/carddiff_perturbed_10x3x8_gpt5mini.yaml --trials 1
```

## Generate Scenario-Adapted Tasks

The scenario-adapter prompt is separate from the case data:

```bash
python scripts/generate_carddiff_scenario_tasks.py --dry-run
```

The prompt template lives at `prompts/carddiff/scenario_adapter_prompt.md`.
Generated task banks feed the case builder in `attacks/carddiff/adapter.py`.

## Validation

Run these checks before changing benchmark data, harness behavior, or SUT
interfaces:

```bash
python -m pytest
python scripts/validate_carddiff_cases.py
python -m compileall -q orchestration.py attacks harness sut utils scripts tests prompts
```

The default tests and validators do not require LLM credentials.

## Relationship To A2ASecBench

A2ASecBench is used as methodological background for scenario-adapter-style
case generation. CardDiffBench is a separate benchmark contribution with its own
AgentCard differential taxonomy and dataset. The archived A2ASecBench snapshot
is kept only for provenance and comparison, not as active experiment code.

## License

CardDiffBench is released under the MIT License. See `LICENSE`.
